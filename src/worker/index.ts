// MCP Vouch — trust-scoring worker (Render cron).
//
// Pipeline:
//   1. Load every active server from the MCP Registry (Supabase).
//   2. For each server with a resolvable npm package (sandbox boundary), run
//      `scanServer()` with a per-scan timeout.
//   3. Upsert the resulting TrustReport into `trust_scores` (UNIQUE server_id).
//
// Concurrency cap + per-scan timeout + npm-only allowlist together implement
// MAN-5 option (a). Servers whose source_url doesn't resolve to an npm package
// are skipped (logged), not scored against — we never score what we couldn't
// safely launch.

import { TrustScanner } from "../scanners/trust-scanner.js";
import {
  blockToCommand,
  resolveInstall,
  type ResolveResult,
} from "./install-resolver.js";
import {
  MemoryExceededError,
  MemoryWatchdog,
  killSubtree,
  readContainerMemoryBytes,
} from "./memory-guard.js";
import {
  getSupabase,
  listActiveServers,
  upsertTrustScore,
  type RegistryServerRow,
} from "./supabase.js";

const DEFAULT_CONCURRENCY = 3;
const DEFAULT_SCAN_TIMEOUT_MS = 60_000;
// Render cron has a hard runtime ceiling; the full registry is far larger than
// any single window. The worker scans the oldest N per run and rotates through.
const DEFAULT_MAX_PER_RUN = 200;
// Container memory watchdog (see memory-guard.ts). Default trip point sits well
// below Render starter's 512Mi hard limit so we can abort + reap a runaway
// `npx -y` install before the kernel OOM-kills the whole cron.
const DEFAULT_MEM_LIMIT_MB = 400;
const DEFAULT_MEM_POLL_MS = 200;

interface RunCounters {
  total: number;
  scanned: number;
  skipped_unresolved: number;
  skipped_oversized: number;
  failed: number;
  timed_out: number;
}

interface ScanOutcome {
  server: RegistryServerRow;
  result: "scanned" | "skipped_unresolved" | "skipped_oversized" | "failed" | "timed_out";
  note?: string;
}

/** Current container memory as a compact "NMi" string, or "?" when unreadable. */
function memMi(): string {
  const b = readContainerMemoryBytes();
  return b == null ? "?" : `${Math.round(b / 1024 / 1024)}Mi`;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timed out after ${ms}ms: ${label}`));
    }, ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

async function scanOne(
  client: ReturnType<typeof getSupabase>,
  server: RegistryServerRow,
  scanTimeoutMs: number,
  memLimitBytes: number,
  memPollMs: number,
): Promise<ScanOutcome> {
  let resolved: ResolveResult;
  try {
    resolved = await resolveInstall(server.source_url);
  } catch (err) {
    return {
      server,
      result: "failed",
      note: `resolveInstall failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!resolved.block) {
    return {
      server,
      result: "skipped_unresolved",
      note: `source_url=${server.source_url ?? "null"} did not resolve to an npm package`,
    };
  }

  const command = blockToCommand(resolved.block);
  // Construct the scanner directly (instead of lib.ts's scanServer wrapper) so
  // we keep a reference and can dispose() it on timeout/error — otherwise the
  // spawned `npx -y <pkg>` child outlives the scan promise and holds RSS until
  // the cron container exits. See issue #1.
  const scanner = new TrustScanner(command);
  // Watchdog races the scan: if the container's memory crosses the guard
  // threshold (almost always during this server's `npx -y` install), reject so
  // we abort + reap before the kernel OOM-kills the whole cron.
  const watchdog = new MemoryWatchdog(memLimitBytes, memPollMs);
  const guard = new Promise<never>((_, reject) => {
    watchdog.start((used) => reject(new MemoryExceededError(used, memLimitBytes)));
  });
  // Prevent an unhandled-rejection crash if the scan wins the race.
  guard.catch(() => {});
  // Hoist the scan promise so we can attach our own rejection handler: when the
  // watchdog wins Promise.race below, this promise LOSES but still settles later
  // — its child was just SIGKILLed, so it rejects with a transport error. With
  // no handler that's an unhandledRejection, which Node 22 treats as fatal and
  // kills the whole 200-server run. The no-op catch marks it handled; the race
  // still reads its resolved value when the scan wins.
  const scanP = withTimeout(scanner.scan(), scanTimeoutMs, `scan ${server.slug}`);
  scanP.catch(() => {});
  try {
    const report = await Promise.race([scanP, guard]);
    await upsertTrustScore(client, {
      server_id: server.id,
      total_score: report.totalScore,
      grade: report.grade,
      checks: report.checks,
      server_name: report.serverInfo.name,
      server_version: report.serverInfo.version,
      protocol_version: report.serverInfo.protocolVersion,
      scanned_at: report.scannedAt,
      scan_duration_ms: report.duration,
    });
    return { server, result: "scanned", note: `${report.totalScore}/${report.grade}` };
  } catch (err) {
    // Force-kill the orphan stdio child. dispose() is idempotent so it's safe
    // even when the failure happened after the scanner already disconnected.
    await scanner.dispose().catch(() => {});
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof MemoryExceededError) {
      // dispose() closes the SDK transport (our direct child); reap the rest of
      // the subtree (npm → node-gyp → prebuild grandchildren) so the install's
      // RSS is released immediately and the next server starts from baseline.
      // Safe at concurrency=1 (the only descendants are this scan's tree).
      const reaped = killSubtree(process.pid);
      return {
        server,
        result: "skipped_oversized",
        note: `${message} — reaped ${reaped} install proc(s)`,
      };
    }
    const timedOut = /^Timed out after/.test(message);
    return {
      server,
      result: timedOut ? "timed_out" : "failed",
      note: message,
    };
  } finally {
    watchdog.stop();
  }
}

/**
 * Drain `queue` with at most `concurrency` workers running scanOne in parallel.
 * Each worker pulls the next index until the queue is empty.
 */
async function drain(
  queue: RegistryServerRow[],
  concurrency: number,
  worker: (server: RegistryServerRow) => Promise<ScanOutcome>,
): Promise<ScanOutcome[]> {
  const results: ScanOutcome[] = [];
  let cursor = 0;

  async function runWorker(): Promise<void> {
    for (;;) {
      const i = cursor++;
      if (i >= queue.length) return;
      const server = queue[i]!;
      const outcome = await worker(server);
      results.push(outcome);
      const tag = outcome.result.toUpperCase();
      const note = outcome.note ? ` — ${outcome.note}` : "";
      // eslint-disable-next-line no-console
      console.log(`[${i + 1}/${queue.length}] mem=${memMi()} ${tag} ${server.slug}${note}`);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, runWorker);
  await Promise.all(workers);
  return results;
}

export async function runWorker(): Promise<RunCounters> {
  const concurrency = envInt("MCP_VOUCH_CONCURRENCY", DEFAULT_CONCURRENCY);
  const scanTimeoutMs = envInt("MCP_VOUCH_SCAN_TIMEOUT_MS", DEFAULT_SCAN_TIMEOUT_MS);
  const maxPerRun = envInt("MCP_VOUCH_MAX_PER_RUN", DEFAULT_MAX_PER_RUN);
  const memLimitBytes = envInt("MCP_VOUCH_MEM_LIMIT_MB", DEFAULT_MEM_LIMIT_MB) * 1024 * 1024;
  const memPollMs = envInt("MCP_VOUCH_MEM_POLL_MS", DEFAULT_MEM_POLL_MS);

  // Diagnostic: confirm the watchdog can actually read the container's cgroup
  // memory in THIS environment. "unreadable" here means the guard is a no-op and
  // we'd OOM for real — the single most important line to check after a crash.
  const probe = readContainerMemoryBytes();
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker: cgroup mem probe = ${probe == null ? "UNREADABLE (watchdog disabled!)" : `${Math.round(probe / 1024 / 1024)}Mi readable`}`,
  );

  const client = getSupabase();
  const servers = await listActiveServers(client, maxPerRun);
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker: ${servers.length} servers this run (cap=${maxPerRun}), concurrency=${concurrency}, timeout=${scanTimeoutMs}ms, mem_guard=${memLimitBytes / 1024 / 1024}Mi`,
  );

  const outcomes = await drain(servers, concurrency, (s) =>
    scanOne(client, s, scanTimeoutMs, memLimitBytes, memPollMs),
  );

  const counters: RunCounters = {
    total: servers.length,
    scanned: outcomes.filter((o) => o.result === "scanned").length,
    skipped_unresolved: outcomes.filter((o) => o.result === "skipped_unresolved").length,
    skipped_oversized: outcomes.filter((o) => o.result === "skipped_oversized").length,
    failed: outcomes.filter((o) => o.result === "failed").length,
    timed_out: outcomes.filter((o) => o.result === "timed_out").length,
  };
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker done: scanned=${counters.scanned} skipped=${counters.skipped_unresolved} oversized=${counters.skipped_oversized} timed_out=${counters.timed_out} failed=${counters.failed} total=${counters.total}`,
  );
  return counters;
}

// Defense in depth: a batch worker that spawns + kills hundreds of child
// processes will occasionally produce a late rejection from an aborted scan's
// transport after we've already moved on. Node 22 treats an unhandledRejection
// as fatal (exits non-zero), which would abort the whole run. Log and keep
// going — scanOne already converts every per-server failure into an outcome.
process.on("unhandledRejection", (reason) => {
  // eslint-disable-next-line no-console
  console.error("mcp-vouch worker: swallowed unhandledRejection:", reason);
});

// Render cron entrypoint.
runWorker().then(
  (c) => {
    // Non-zero exit when nothing scanned AND there are servers to scan, so the
    // cron shows red in Render. A clean run with skipped/failed > 0 but
    // scanned > 0 is still "green" — partial coverage is normal.
    if (c.total > 0 && c.scanned === 0) process.exit(2);
    process.exit(0);
  },
  (err) => {
    // eslint-disable-next-line no-console
    console.error("mcp-vouch worker fatal:", err);
    process.exit(1);
  },
);
