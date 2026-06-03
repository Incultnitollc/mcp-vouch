// Regression test for issue #1: when withTimeout() in the worker rejects a
// hanging scan, TrustScanner.dispose() must force-kill the spawned stdio
// child so it cannot survive the cron run and hold RSS.

import { describe, it, expect, vi } from "vitest";
import { TrustScanner } from "../src/scanners/trust-scanner.js";

// The scanner's command parser splits on whitespace (matches `npx -y pkg`), so
// any absolute path containing a space (this repo lives under "MCP Vouch - 3")
// would be torn apart. The fixture is referenced as a project-relative path —
// vitest runs from the repo root so node resolves it correctly.
const COMMAND = "node test/fixtures/hanging-server.mjs";

// Local copy of the worker's withTimeout — mirrors src/worker/index.ts exactly.
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

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForExit(pid: number, maxMs = 5_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    if (!pidAlive(pid)) return;
    await new Promise((r) => setTimeout(r, 25));
  }
}

interface TransportLike {
  pid: number | null;
}
interface ClientWithTransport {
  _transport?: TransportLike;
}
interface ScannerInternals {
  client: ClientWithTransport | null;
}

describe("TrustScanner.dispose", () => {
  it("kills the spawned stdio child after a withTimeout() rejection", async () => {
    const scanner = new TrustScanner(COMMAND);
    const disposeSpy = vi.spyOn(scanner, "dispose");

    // Kick off the scan; it will hang inside connect() awaiting initialize.
    const scanPromise = scanner.scan();
    // Make sure the unhandled-rejection from scanPromise (after dispose closes
    // the transport) doesn't leak to the test runner.
    scanPromise.catch(() => {});

    // Mirror the worker's pattern: race the hanging scan against a short timeout.
    await expect(withTimeout(scanPromise, 100, "test")).rejects.toThrow(/Timed out/);

    // Give the StdioClientTransport a beat to actually finish spawning the
    // child (the 100ms timeout can fire before the 'spawn' event lands on slow
    // CI runners).
    const internals = scanner as unknown as ScannerInternals;
    let pid = internals.client?._transport?.pid ?? null;
    const deadline = Date.now() + 2_000;
    while (!pid && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
      pid = internals.client?._transport?.pid ?? null;
    }

    expect(pid).not.toBeNull();
    expect(pidAlive(pid as number)).toBe(true);

    // Force-kill the orphan exactly as the worker now does.
    await scanner.dispose().catch(() => {});
    expect(disposeSpy).toHaveBeenCalled();

    await waitForExit(pid as number);
    expect(pidAlive(pid as number)).toBe(false);
  }, 15_000);

  it("is idempotent — calling dispose() twice is safe", async () => {
    const scanner = new TrustScanner(COMMAND);
    const scanPromise = scanner.scan();
    scanPromise.catch(() => {});

    await expect(withTimeout(scanPromise, 100, "test")).rejects.toThrow(/Timed out/);

    await scanner.dispose();
    await expect(scanner.dispose()).resolves.toBeUndefined();
  }, 15_000);
});
