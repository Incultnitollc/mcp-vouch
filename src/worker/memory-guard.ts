// MCP Vouch worker — container memory watchdog.
//
// Why this exists: each `npx -y <pkg>` install pulls the server's full
// transitive npm tree. Some trees bundle native binaries (node-gyp /
// prebuild-install) or are simply huge; extracting them spikes RSS. On Render
// starter (512Mi) a SINGLE such install — even at concurrency=1 — can push the
// whole container over the limit and the cron is OOM-killed mid-install
// (confirmed 2026-06-11: prebuild-install + posthog-node tree → 512Mi kill).
//
// A top-level "skip packages with build scripts" denylist misses this, because
// the memory bomb is often a TRANSITIVE dependency, not the package we resolve.
//
// So instead of predicting which install is heavy, we measure: poll the
// container's own memory accounting (Linux cgroup) while a scan runs, and when
// usage crosses a safety threshold BELOW the hard limit, abort that scan and
// kill its process subtree. The container never reaches the kernel OOM ceiling.
//
// Everything here degrades to a no-op off Linux (no cgroup / no /proc), so the
// CLI and local tests are unaffected.

import { readFileSync, readdirSync } from "node:fs";

/** Thrown when the container crosses the memory threshold during a scan. */
export class MemoryExceededError extends Error {
  constructor(public readonly usedBytes: number, public readonly limitBytes: number) {
    super(
      `Container memory ${(usedBytes / 1024 / 1024).toFixed(0)}Mi crossed guard ` +
        `threshold ${(limitBytes / 1024 / 1024).toFixed(0)}Mi`,
    );
    this.name = "MemoryExceededError";
  }
}

// cgroup v2 (current Render) then v1 fallback.
const CGROUP_V2 = "/sys/fs/cgroup/memory.current";
const CGROUP_V1 = "/sys/fs/cgroup/memory/memory.usage_in_bytes";

type FileReader = (path: string) => string | null;

const defaultReader: FileReader = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
};

/** Parse a cgroup memory file body. Returns bytes, or null for "max"/garbage. */
export function parseCgroupMemoryBytes(raw: string | null): number | null {
  if (raw == null) return null;
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed === "max") return null;
  const n = Number.parseInt(trimmed, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * cgroup-reported memory for this container in bytes, or null when no cgroup
 * accounting is readable (non-Linux dev box, missing files, or — observed on
 * Render — a container whose cgroup files aren't exposed at the expected path).
 * cgroup v2 first, v1 fallback. This is ONE of two signals the watchdog uses.
 */
export function readContainerMemoryBytes(read: FileReader = defaultReader): number | null {
  const v2 = parseCgroupMemoryBytes(read(CGROUP_V2));
  if (v2 != null) return v2;
  return parseCgroupMemoryBytes(read(CGROUP_V1));
}

// Linux page size. getconf PAGESIZE is 4096 on every arch Render runs (x86_64,
// arm64); Node has no portable getpagesize(), so we assume it.
const PAGE_SIZE = 4096;

/**
 * Resident set size from a /proc/<pid>/statm body, in bytes. statm fields are
 * "size resident shared ..." in pages — field 2 (resident) is the one that
 * counts toward the cgroup/OOM budget for anonymous memory.
 */
export function parseStatmResidentBytes(content: string): number | null {
  const fields = content.trim().split(/\s+/);
  const resident = Number.parseInt(fields[1] ?? "", 10);
  return Number.isFinite(resident) ? resident * PAGE_SIZE : null;
}

function procResidentBytes(pid: number): number | null {
  try {
    return parseStatmResidentBytes(readFileSync(`/proc/${pid}/statm`, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Summed RSS of the worker process tree (rootPid + every descendant) in bytes,
 * or null when /proc is absent (non-Linux). This is the cgroup-independent
 * fallback signal: it needs nothing but /proc and so works in containers where
 * the cgroup memory files aren't readable. It slightly UNDER-counts vs cgroup
 * (no page cache), which is fine — anonymous RSS is what actually drives OOM
 * kills, and we run the threshold with headroom anyway.
 */
export function treeRssBytes(rootPid: number): number | null {
  const root = procResidentBytes(rootPid);
  if (root == null) return null; // no /proc → signal unavailable
  let total = root;
  for (const pid of descendantPids(rootPid)) {
    total += procResidentBytes(pid) ?? 0;
  }
  return total;
}

/**
 * The watchdog's memory signal: the MAX of the cgroup reading and the process
 * tree's summed RSS. Using max means a failure of EITHER source can't blind the
 * guard — if cgroup is unreadable we still see tree RSS, and vice versa. Returns
 * null only when both are unavailable (non-Linux dev box → guard is a no-op).
 */
export function currentMemoryBytes(rootPid: number = process.pid): number | null {
  const cg = readContainerMemoryBytes();
  const rss = treeRssBytes(rootPid);
  if (cg == null && rss == null) return null;
  return Math.max(cg ?? 0, rss ?? 0);
}

interface ProcEntry {
  pid: number;
  ppid: number;
}

/**
 * Extract pid + ppid from /proc/<pid>/stat. The comm field (2nd) is wrapped in
 * parens and may itself contain spaces or ')', so we split after the LAST ')':
 * the field immediately following is `state`, and the one after that is ppid.
 */
export function parseProcStat(content: string): ProcEntry | null {
  const pidMatch = content.match(/^(\d+)\s+\(/);
  const close = content.lastIndexOf(")");
  if (!pidMatch || close === -1) return null;
  const after = content.slice(close + 1).trim().split(/\s+/);
  // after = [state, ppid, ...]
  const ppid = Number.parseInt(after[1] ?? "", 10);
  if (!Number.isFinite(ppid)) return null;
  return { pid: Number.parseInt(pidMatch[1]!, 10), ppid };
}

/** Read every /proc/<pid>/stat into a flat pid→ppid snapshot (Linux only). */
function readProcSnapshot(): ProcEntry[] {
  let names: string[];
  try {
    names = readdirSync("/proc");
  } catch {
    return [];
  }
  const out: ProcEntry[] = [];
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const entry = parseProcStat(readFileSync(`/proc/${name}/stat`, "utf8"));
      if (entry) out.push(entry);
    } catch {
      // process exited between readdir and read — skip.
    }
  }
  return out;
}

/**
 * All descendant pids of rootPid (children, grandchildren, …), excluding
 * rootPid itself. Used to reap the entire `npx`→`npm`→`node-gyp` subtree so no
 * orphan keeps holding RSS after we abort a scan. `snapshot` is injectable for
 * tests; defaults to a live /proc read.
 */
export function descendantPids(rootPid: number, snapshot: ProcEntry[] = readProcSnapshot()): number[] {
  const childrenOf = new Map<number, number[]>();
  for (const { pid, ppid } of snapshot) {
    const list = childrenOf.get(ppid);
    if (list) list.push(pid);
    else childrenOf.set(ppid, [pid]);
  }
  const out: number[] = [];
  const stack = [...(childrenOf.get(rootPid) ?? [])];
  while (stack.length) {
    const pid = stack.pop()!;
    out.push(pid);
    const kids = childrenOf.get(pid);
    if (kids) stack.push(...kids);
  }
  return out;
}

/**
 * SIGKILL every descendant of rootPid. Best-effort: a pid that already exited
 * throws ESRCH, which we swallow. Never kills rootPid (our own worker).
 */
export function killSubtree(rootPid: number): number {
  let killed = 0;
  for (const pid of descendantPids(rootPid)) {
    try {
      process.kill(pid, "SIGKILL");
      killed++;
    } catch {
      // already gone / not permitted — ignore.
    }
  }
  return killed;
}

/**
 * Poll the memory signal every `pollMs`. The first sample at or above
 * `limitBytes` invokes `onExceed` once and stops polling. No-op (never fires)
 * when the sampler returns null on every tick (non-Linux: no cgroup AND no
 * /proc). `sample` is injectable for tests; defaults to currentMemoryBytes
 * (max of cgroup reading and process-tree RSS). Call stop() to clear the timer.
 */
export class MemoryWatchdog {
  private timer: ReturnType<typeof setInterval> | null = null;
  private fired = false;

  constructor(
    private readonly limitBytes: number,
    private readonly pollMs: number,
    private readonly sample: () => number | null = () => currentMemoryBytes(),
  ) {}

  start(onExceed: (used: number) => void): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      const used = this.sample();
      if (used != null && used >= this.limitBytes && !this.fired) {
        this.fired = true;
        this.stop();
        onExceed(used);
      }
    }, this.pollMs);
    // Don't let the poll timer keep the event loop alive on its own.
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
