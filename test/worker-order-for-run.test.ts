// Tests for orderForRun — the batch rotation that stops the worker getting
// pinned on one poison set of unscanned servers every run.

import { describe, expect, it } from "vitest";
import { orderForRun } from "../src/worker/supabase.js";

// Minimal row factory. scannedAt=null => unscanned (sorts/rotates); a timestamp
// => scored.
function row(id: string, scannedAt: string | null) {
  return {
    id,
    slug: id,
    name: id,
    repo_url: null,
    card_summary_json: null,
    server_versions: null,
    trust_scores: scannedAt ? [{ scanned_at: scannedAt }] : null,
  };
}

const ROTATE_MS = 30 * 60 * 1000;

describe("orderForRun", () => {
  it("rotates the unscanned window so consecutive runs scan different servers", () => {
    const unscanned = Array.from({ length: 10 }, (_, i) => row(`u${i}`, null));

    // Window of 5 over 10 unscanned => 2 batches.
    const run0 = orderForRun(unscanned, 5, 0).slice(0, 5).map((r) => r.id);
    const run1 = orderForRun(unscanned, 5, ROTATE_MS).slice(0, 5).map((r) => r.id);

    expect(run0).toEqual(["u0", "u1", "u2", "u3", "u4"]);
    expect(run1).toEqual(["u5", "u6", "u7", "u8", "u9"]); // advanced one batch
    expect(run1).not.toEqual(run0);
  });

  it("wraps the rotation back to the start after a full pass", () => {
    const unscanned = Array.from({ length: 10 }, (_, i) => row(`u${i}`, null));
    const run0 = orderForRun(unscanned, 5, 0).slice(0, 5).map((r) => r.id);
    const run2 = orderForRun(unscanned, 5, 2 * ROTATE_MS).slice(0, 5).map((r) => r.id);
    expect(run2).toEqual(run0); // 2 batches → batchIndex 2 % 2 === 0
  });

  it("does not rotate when unscanned fits within one batch", () => {
    const unscanned = [row("a", null), row("b", null), row("c", null)];
    const t0 = orderForRun(unscanned, 5, 0).map((r) => r.id);
    const t1 = orderForRun(unscanned, 5, 99 * ROTATE_MS).map((r) => r.id);
    expect(t0).toEqual(["a", "b", "c"]);
    expect(t1).toEqual(t0);
  });

  it("puts all unscanned ahead of scored, and scored oldest-first", () => {
    const rows = [
      row("scored-new", "2026-06-12T10:00:00Z"),
      row("unscanned", null),
      row("scored-old", "2026-06-01T10:00:00Z"),
    ];
    const ids = orderForRun(rows, 10, 0).map((r) => r.id);
    expect(ids).toEqual(["unscanned", "scored-old", "scored-new"]);
  });
});
