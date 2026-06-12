// MCP Vouch — shared type contracts
//
// These types are the contract between the scanner, the reporter, and (later)
// the MCP Registry integration that stores a TrustReport in Supabase and renders
// it as a badge on each listing. Keep everything JSON-serializable.

/** Outcome of a single security check. */
export type CheckStatus = "PASS" | "FAIL" | "WARN" | "SKIP";

/** Letter grade derived from the total trust score. */
export type Grade = "A" | "B" | "C" | "D" | "F";

/** Result of one OWASP MCP Top 10 check. */
export interface CheckResult {
  /** Stable id, e.g. "MCP01". */
  id: string;
  /** Human-readable name, e.g. "Tool Poisoning". */
  name: string;
  /** Outcome. SKIP = not applicable to this transport/server. */
  status: CheckStatus;
  /** Points awarded for this check, 0–10. SKIP checks are excluded from scoring. */
  score: number;
  /** Honest, human-readable explanation of what was tested and what was found. */
  details: string;
  /** Wall-clock time spent on this check, in milliseconds. */
  duration: number;
}

/** Identity of the scanned server, as reported during MCP initialize. */
export interface ServerInfo {
  name: string;
  version: string;
  protocolVersion: string;
}

/** Full trust report for a single MCP server scan. */
export interface TrustReport {
  /** 0–100. Sum of awarded points over applicable (non-SKIP) checks, scaled to 100. */
  totalScore: number;
  /** Letter grade derived from totalScore. */
  grade: Grade;
  /** All 10 check results, in MCP01–MCP10 order. */
  checks: CheckResult[];
  /** Identity of the scanned server. */
  serverInfo: ServerInfo;
  /** ISO 8601 timestamp of when the scan ran. */
  scannedAt: string;
  /** Total wall-clock duration of the whole scan, in milliseconds. */
  duration: number;
}

/** Maximum points any single check can award. */
export const MAX_POINTS_PER_CHECK = 10;

/** Remote (network) MCP transports the scanner can connect over. */
export type RemoteTransport = "streamable-http" | "sse";

/**
 * What the scanner connects to. The registry yields one of two shapes:
 *   - `stdio`: an npm package launched locally via `npx -y` (the sandbox path,
 *     subject to the worker's memory watchdog + npm-cache cleanup).
 *   - `http`: a hosted remote endpoint (`card_summary_json.remotes[]`). Nothing
 *     is launched locally, so the HTTP path has no OOM/sandbox concern — and it
 *     activates the auth (MCP05) and transport (MCP06) checks that stdio skips.
 */
export type ScanTarget =
  | { kind: "stdio"; command: string; extraEnv?: Record<string, string> }
  | { kind: "http"; url: string; transport: RemoteTransport };
