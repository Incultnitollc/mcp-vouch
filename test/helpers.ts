// Shared test helpers for the MCP Vouch trust-scanner suite.
//
// The scanner's scoring/grade methods and per-check classifiers are private.
// We exercise them without spawning a real MCP server by:
//   (a) casting the scanner to a typed view that exposes the private methods, and
//   (b) injecting a fake MCP client into the private `client` field so the
//       per-check methods (which call `this.requireClient()`) run against stubs.

import { vi } from "vitest";
import { TrustScanner } from "../src/scanners/trust-scanner.js";
import type { CheckResult } from "../src/types/index.js";

/** A tool entry as returned by `client.listTools()`. */
export interface FakeTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** Minimal shape of the MCP client surface the checks actually call. */
export interface FakeClient {
  listTools: ReturnType<typeof vi.fn>;
  callTool: ReturnType<typeof vi.fn>;
  listResources: ReturnType<typeof vi.fn>;
  listResourceTemplates: ReturnType<typeof vi.fn>;
  readResource: ReturnType<typeof vi.fn>;
  getServerCapabilities: ReturnType<typeof vi.fn>;
}

/** Typed view onto the private methods/fields we need to reach in tests. */
export interface ScannerInternals {
  client: unknown;
  computeTotalScore(checks: CheckResult[]): number;
  toGrade(score: number): "A" | "B" | "C" | "D" | "F";
  checkToolPoisoning(): Promise<Omit<CheckResult, "id" | "name" | "duration">>;
  checkCapabilityExposure(): Promise<Omit<CheckResult, "id" | "name" | "duration">>;
  checkShadowTools(): Promise<Omit<CheckResult, "id" | "name" | "duration">>;
}

/** Build a scanner exposed as its internal view, with an optional fake client. */
export function makeScanner(
  command = "npx -y @modelcontextprotocol/server-everything",
  client?: Partial<FakeClient>,
): ScannerInternals {
  const scanner = new TrustScanner(command) as unknown as ScannerInternals;
  if (client) scanner.client = client;
  return scanner;
}

/** A fake client whose `listTools` returns the given synthetic tool list. */
export function clientWithTools(tools: FakeTool[]): Partial<FakeClient> {
  return {
    listTools: vi.fn().mockResolvedValue({ tools }),
  };
}

/** Convenience: build a CheckResult with sensible defaults for scoring tests. */
export function check(
  status: CheckResult["status"],
  score: number,
  id = "MCPxx",
): CheckResult {
  return { id, name: id, status, score, details: "", duration: 0 };
}
