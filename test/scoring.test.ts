// computeTotalScore: SKIP checks must be EXCLUDED from the denominator.
// Score = round( sum(score over non-SKIP checks) / (count(non-SKIP) * 10) * 100 ).

import { describe, it, expect } from "vitest";
import { MAX_POINTS_PER_CHECK } from "../src/types/index.js";
import { makeScanner, check } from "./helpers.js";

describe("computeTotalScore", () => {
  it("returns 0 when every check is SKIP (empty denominator)", () => {
    const s = makeScanner();
    const checks = [check("SKIP", 0), check("SKIP", 0), check("SKIP", 0)];
    expect(s.computeTotalScore(checks)).toBe(0);
  });

  it("excludes SKIP checks from the denominator", () => {
    const s = makeScanner();
    // Two PASS (10 each) + three SKIP. Denominator is 2*10 = 20, not 50.
    const checks = [
      check("PASS", 10),
      check("PASS", 10),
      check("SKIP", 0),
      check("SKIP", 0),
      check("SKIP", 0),
    ];
    // 20 / 20 * 100 = 100. If SKIPs counted, it would be 40.
    expect(s.computeTotalScore(checks)).toBe(100);
  });

  it("scales a PASS/WARN mix correctly and rounds", () => {
    const s = makeScanner();
    // 3 scored checks: 10 + 5 + 8 = 23 of 30 -> 76.666 -> 77.
    const checks = [check("PASS", 10), check("WARN", 5), check("PASS", 8)];
    expect(s.computeTotalScore(checks)).toBe(77);
  });

  it("matches the known live fixture: 81/100 with two SKIPs", () => {
    const s = makeScanner();
    // Mirrors the live server-everything scan: MCP05 + MCP06 SKIP, 8 scored
    // checks summing to 65 of 80 -> 81.25 -> 81.
    const checks = [
      check("PASS", 10, "MCP01"), // Tool Poisoning
      check("WARN", 5, "MCP02"), // Input Validation
      check("PASS", 10, "MCP03"), // Resource Injection
      check("WARN", 4, "MCP04"), // Capability Exposure
      check("SKIP", 0, "MCP05"), // Authentication (excluded)
      check("SKIP", 0, "MCP06"), // Transport (excluded)
      check("PASS", 10, "MCP07"), // Shadow Tools
      check("PASS", 10, "MCP08"), // Audit/Telemetry
      check("WARN", 8, "MCP09"), // Rate Limiting
      check("PASS", 8, "MCP10"), // Supply Chain (pinned version)
    ];
    const scored = checks.filter((c) => c.status !== "SKIP");
    const earned = scored.reduce((sum, c) => sum + c.score, 0);
    const possible = scored.length * MAX_POINTS_PER_CHECK;
    // Fixture sums to 65 of 80, exactly the documented 81.25 -> 81.
    expect(earned).toBe(65);
    expect(possible).toBe(80);
    expect(s.computeTotalScore(checks)).toBe(Math.round((earned / possible) * 100));
    expect(s.computeTotalScore(checks)).toBe(81);
  });

  it("treats FAIL (score 0) as scored, not skipped", () => {
    const s = makeScanner();
    // 1 FAIL (0) + 1 PASS (10): denominator 20 -> 50, not 100.
    const checks = [check("FAIL", 0), check("PASS", 10)];
    expect(s.computeTotalScore(checks)).toBe(50);
  });
});
