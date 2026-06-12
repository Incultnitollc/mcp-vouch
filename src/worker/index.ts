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

import { rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { argv } from "node:process";
import { pathToFileURL } from "node:url";
import { TrustScanner, classifyRemoteError } from "../scanners/trust-scanner.js";
import type { ScanTarget } from "../types/index.js";
import { resolveScanTarget } from "./install-resolver.js";
import {
  MemoryExceededError,
  MemoryWatchdog,
  currentMemoryBytes,
  killSubtree,
  readContainerMemoryBytes,
  treeRssBytes,
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
const DEFAULT_MEM_LIMIT_MB = 360;
const DEFAULT_MEM_POLL_MS = 200;

interface RunCounters {
  total: number;
  scanned: number;
  skipped_unresolved: number;
  skipped_oversized: number;
  skipped_auth_required: number;
  skipped_challenge: number;
  failed: number;
  timed_out: number;
}

type ScanResult =
  | "scanned"
  | "skipped_unresolved"
  | "skipped_oversized"
  | "skipped_auth_required"
  | "skipped_challenge"
  | "failed"
  | "timed_out";

interface ScanOutcome {
  server: RegistryServerRow;
  result: ScanResult;
  note?: string;
}

/** Current memory signal as a compact "NMi" string, or "?" when unreadable. */
function memMi(): string {
  const b = currentMemoryBytes();
  return b == null ? "?" : `${Math.round(b / 1024 / 1024)}Mi`;
}

/**
 * Delete the npm/npx cache after each scan. THE actual OOM root cause: on Render
 * `~/.npm` is RAM-backed (tmpfs), so every `npx -y <pkg>` writes the package +
 * its dependency tree there and never removes it. Memory ratchets up install by
 * install — never freed by killing processes ("reaped 0") because it's cached
 * FILES, not process RSS — until it crosses 512Mi (the original OOM) or pins the
 * watchdog above its threshold so every later server is skipped (scanned=0).
 * Clearing these dirs between scans keeps memory flat at baseline + one install.
 * `npm_config_cache` honored if set; else the default ~/.npm (HOME=/opt/render).
 */
async function cleanNpmCache(): Promise<void> {
  const cacheRoot = process.env.npm_config_cache ?? join(homedir(), ".npm");
  // _npx holds the installed package trees; _cacache holds downloaded tarballs.
  await Promise.all(
    ["_npx", "_cacache"].map((sub) =>
      rm(join(cacheRoot, sub), { recursive: true, force: true }).catch(() => {}),
    ),
  );
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
  let target: ScanTarget | null;
  try {
    target = await resolveScanTarget(server);
  } catch (err) {
    return {
      server,
      result: "failed",
      note: `resolveScanTarget failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (!target) {
    return {
      server,
      result: "skipped_unresolved",
      note: `source_url=${server.source_url ?? "null"} resolved to neither an npm package nor a remote endpoint`,
    };
  }

  // Remote HTTP endpoints launch nothing locally: no OOM/sandbox risk, so they
  // skip the memory watchdog + npm-cache machinery and take the simpler path.
  if (target.kind === "http") {
    return scanRemote(client, server, target, scanTimeoutMs);
  }
  return scanStdio(client, server, target, scanTimeoutMs, memLimitBytes, memPollMs);
}

/**
 * Scan a remote (HTTP) MCP endpoint. Connects unauthenticated; handshake
 * failures are classified (classifyRemoteError) so an auth wall or a Cloudflare
 * challenge is recorded as a SKIP rather than a failure — neither reddens the
 * cron (see exitCodeForRun).
 */
async function scanRemote(
  client: ReturnType<typeof getSupabase>,
  server: RegistryServerRow,
  target: Extract<ScanTarget, { kind: "http" }>,
  scanTimeoutMs: number,
): Promise<ScanOutcome> {
  const scanner = new TrustScanner(target);
  try {
    const report = await withTimeout(scanner.scan(), scanTimeoutMs, `scan ${server.slug}`);
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
    return { server, result: "scanned", note: `${report.totalScore}/${report.grade} (http)` };
  } catch (err) {
    await scanner.dispose().catch(() => {});
    const message = err instanceof Error ? err.message : String(err);
    if (/^Timed out after/.test(message)) {
      return { server, result: "timed_out", note: message };
    }
    const kind = classifyRemoteError(err);
    if (kind === "auth") {
      return { server, result: "skipped_auth_required", note: `auth required: ${message}` };
    }
    if (kind === "challenge") {
      return { server, result: "skipped_challenge", note: `bot challenge: ${message}` };
    }
    return { server, result: "failed", note: message };
  }
}

async function scanStdio(
  client: ReturnType<typeof getSupabase>,
  server: RegistryServerRow,
  target: Extract<ScanTarget, { kind: "stdio" }>,
  scanTimeoutMs: number,
  memLimitBytes: number,
  memPollMs: number,
): Promise<ScanOutcome> {
  const command = target.command;
  // Construct the scanner directly (instead of lib.ts's scanServer wrapper) so
  // we keep a reference and can dispose() it on timeout/error — otherwise the
  // spawned `npx -y <pkg>` child outlives the scan promise and holds RSS until
  // the cron container exits. See issue #1.
  // NOTE: ignore-scripts was tried (commit 8442591) to suppress native-build
  // memory spikes but did not stop the ~300-350s deaths and risked breaking npx
  // bin resolution (zero new scores while live), so it's reverted. The batch
  // rotation in listActiveServers is the real progress fix; the memory watchdog
  // is the per-server backstop. TrustScanner still accepts extraEnv if needed.
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
    // Free this scan's install footprint from tmpfs so memory doesn't ratchet
    // up across the run. This is the core OOM fix — see cleanNpmCache.
    await cleanNpmCache();
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

  // Diagnostic: which memory signal(s) work in THIS container? The watchdog uses
  // max(cgroup, tree-RSS), so it stays armed as long as AT LEAST ONE is non-null.
  // "both null" would mean the guard is a no-op and we'd OOM for real.
  const cg = readContainerMemoryBytes();
  const rss = treeRssBytes(process.pid);
  const fmt = (b: number | null) => (b == null ? "null" : `${Math.round(b / 1024 / 1024)}Mi`);
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker: mem signals — cgroup=${fmt(cg)} treeRSS=${fmt(rss)}` +
      (cg == null && rss == null ? " — BOTH NULL, WATCHDOG DISABLED!" : " — watchdog armed"),
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

  const count = (r: ScanResult) => outcomes.filter((o) => o.result === r).length;
  const counters: RunCounters = {
    total: servers.length,
    scanned: count("scanned"),
    skipped_unresolved: count("skipped_unresolved"),
    skipped_oversized: count("skipped_oversized"),
    skipped_auth_required: count("skipped_auth_required"),
    skipped_challenge: count("skipped_challenge"),
    failed: count("failed"),
    timed_out: count("timed_out"),
  };
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker done: scanned=${counters.scanned} skipped=${counters.skipped_unresolved} oversized=${counters.skipped_oversized} auth=${counters.skipped_auth_required} challenge=${counters.skipped_challenge} timed_out=${counters.timed_out} failed=${counters.failed} total=${counters.total}`,
  );
  return counters;
}

/**
 * Process exit code from a run's counters.
 *
 * A slice we couldn't inspect is NOT a failure — there's simply nothing to
 * score. That covers servers that resolved to no target (skipped_unresolved),
 * remote endpoints behind an auth wall (skipped_auth_required), and remote
 * endpoints behind a bot challenge (skipped_challenge). All are normal because
 * most of the registry is non-npm/auth-gated and the batch rotates. The old rule
 * (`total > 0 && scanned === 0 -> 2`) reddened those runs and trained the team
 * to ignore the cron's status (alert fatigue).
 *
 * Red (exit 2) only when servers we COULD actually inspect all failed to produce
 * a score — i.e. inspectable > 0 and scanned === 0. That's a real regression
 * worth an alert; everything else is green.
 */
export function exitCodeForRun(c: RunCounters): 0 | 2 {
  const uninspectable =
    c.skipped_unresolved + c.skipped_auth_required + c.skipped_challenge;
  const inspectable = c.total - uninspectable;
  return inspectable > 0 && c.scanned === 0 ? 2 : 0;
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

// Render cron entrypoint. Guard so importing this module (e.g. from tests, to
// reach exitCodeForRun) doesn't kick off a real worker run + process.exit.
const isDirectRun = argv[1] != null && import.meta.url === pathToFileURL(argv[1]).href;
if (isDirectRun) {
  runWorker().then(
    (c) => {
      // Red only when servers we could resolve all failed to score (see
      // exitCodeForRun). An all-non-npm slice exits 0 — nothing to scan ≠ failure.
      process.exit(exitCodeForRun(c));
    },
    (err) => {
      // eslint-disable-next-line no-console
      console.error("mcp-vouch worker fatal:", err);
      process.exit(1);
    },
  );
}
