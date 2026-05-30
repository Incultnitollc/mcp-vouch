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

import { scanServer } from "../lib.js";
import {
  blockToCommand,
  resolveInstall,
  type ResolveResult,
} from "./install-resolver.js";
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

interface RunCounters {
  total: number;
  scanned: number;
  skipped_unresolved: number;
  failed: number;
  timed_out: number;
}

interface ScanOutcome {
  server: RegistryServerRow;
  result: "scanned" | "skipped_unresolved" | "failed" | "timed_out";
  note?: string;
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
  try {
    const report = await withTimeout(
      scanServer(command),
      scanTimeoutMs,
      `scan ${server.slug}`,
    );
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
    const message = err instanceof Error ? err.message : String(err);
    const timedOut = /^Timed out after/.test(message);
    return {
      server,
      result: timedOut ? "timed_out" : "failed",
      note: message,
    };
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
      console.log(`[${i + 1}/${queue.length}] ${tag} ${server.slug}${note}`);
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

  const client = getSupabase();
  const servers = await listActiveServers(client, maxPerRun);
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker: ${servers.length} servers this run (cap=${maxPerRun}), concurrency=${concurrency}, timeout=${scanTimeoutMs}ms`,
  );

  const outcomes = await drain(servers, concurrency, (s) =>
    scanOne(client, s, scanTimeoutMs),
  );

  const counters: RunCounters = {
    total: servers.length,
    scanned: outcomes.filter((o) => o.result === "scanned").length,
    skipped_unresolved: outcomes.filter((o) => o.result === "skipped_unresolved").length,
    failed: outcomes.filter((o) => o.result === "failed").length,
    timed_out: outcomes.filter((o) => o.result === "timed_out").length,
  };
  // eslint-disable-next-line no-console
  console.log(
    `mcp-vouch worker done: scanned=${counters.scanned} skipped=${counters.skipped_unresolved} timed_out=${counters.timed_out} failed=${counters.failed} total=${counters.total}`,
  );
  return counters;
}

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
