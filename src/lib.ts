// MCP Vouch — public library surface
//
// This is the import entry point for programmatic consumers (the MCP Registry
// scoring worker, tests, future hosted dashboard). The CLI in index.ts is a
// thin wrapper over the same TrustScanner. Keep this surface stable and
// JSON-serializable end to end.

export { TrustScanner } from "./scanners/trust-scanner.js";
export type {
  CheckStatus,
  Grade,
  CheckResult,
  ServerInfo,
  TrustReport,
} from "./types/index.js";
export { MAX_POINTS_PER_CHECK } from "./types/index.js";

import { TrustScanner } from "./scanners/trust-scanner.js";
import type { TrustReport } from "./types/index.js";

/**
 * Scan a single MCP server and return its trust report.
 *
 * Convenience wrapper over `new TrustScanner(command).scan()` for callers that
 * just want a report from a launch command (e.g. the registry scoring worker
 * iterating over server rows).
 *
 * @param command Full stdio launch command, e.g.
 *   `"npx -y @modelcontextprotocol/server-everything"`.
 * @returns The full {@link TrustReport} (score, grade, per-check results).
 */
export function scanServer(command: string): Promise<TrustReport> {
  return new TrustScanner(command).scan();
}
