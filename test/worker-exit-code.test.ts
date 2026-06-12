// Tests for exitCodeForRun — the cron status decision. The bug being fixed:
// an all-non-npm slice (scanned=0) used to exit 2 and red the cron, training
// the team to ignore it. Red must mean "resolvable servers all failed".

import { describe, expect, it } from "vitest";
import { exitCodeForRun } from "../src/worker/index.js";

function counters(over: Partial<{
  total: number;
  scanned: number;
  skipped_unresolved: number;
  skipped_oversized: number;
  skipped_auth_required: number;
  skipped_challenge: number;
  failed: number;
  timed_out: number;
}> = {}) {
  return {
    total: 0,
    scanned: 0,
    skipped_unresolved: 0,
    skipped_oversized: 0,
    skipped_auth_required: 0,
    skipped_challenge: 0,
    failed: 0,
    timed_out: 0,
    ...over,
  };
}

describe("exitCodeForRun", () => {
  it("greens an all-non-npm slice (every server unresolved)", () => {
    expect(exitCodeForRun(counters({ total: 50, skipped_unresolved: 50 }))).toBe(0);
  });

  it("greens an empty run (nothing in the registry window)", () => {
    expect(exitCodeForRun(counters({ total: 0 }))).toBe(0);
  });

  it("greens partial coverage (some scanned, some skipped/failed)", () => {
    expect(
      exitCodeForRun(counters({ total: 10, scanned: 4, skipped_unresolved: 5, failed: 1 })),
    ).toBe(0);
  });

  it("reds when every resolvable server failed to score", () => {
    // 3 npm servers, all timed out / failed, none scored → real regression.
    expect(
      exitCodeForRun(counters({ total: 8, skipped_unresolved: 5, failed: 2, timed_out: 1 })),
    ).toBe(2);
  });

  it("reds when resolvable servers were all OOM-reaped", () => {
    expect(
      exitCodeForRun(counters({ total: 6, skipped_unresolved: 4, skipped_oversized: 2 })),
    ).toBe(2);
  });

  it("greens as soon as at least one resolvable server scored", () => {
    expect(
      exitCodeForRun(counters({ total: 6, skipped_unresolved: 4, scanned: 1, failed: 1 })),
    ).toBe(0);
  });

  it("greens an all-auth-gated remote slice (couldn't inspect ≠ failure)", () => {
    expect(
      exitCodeForRun(counters({ total: 12, skipped_auth_required: 12 })),
    ).toBe(0);
  });

  it("greens an all-Cloudflare-challenge slice", () => {
    expect(
      exitCodeForRun(counters({ total: 8, skipped_challenge: 8 })),
    ).toBe(0);
  });

  it("greens a mixed uninspectable slice (unresolved + auth + challenge, none failed)", () => {
    expect(
      exitCodeForRun(
        counters({ total: 9, skipped_unresolved: 3, skipped_auth_required: 4, skipped_challenge: 2 }),
      ),
    ).toBe(0);
  });

  it("reds when the only inspectable remote (past the auth/challenge walls) failed", () => {
    // 5 auth-gated + 2 challenged + 1 reachable remote that errored → the one we
    // could actually inspect failed, so this is a real regression.
    expect(
      exitCodeForRun(
        counters({ total: 8, skipped_auth_required: 5, skipped_challenge: 2, failed: 1 }),
      ),
    ).toBe(2);
  });
});
