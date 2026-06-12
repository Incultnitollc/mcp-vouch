// Tests for remote (HTTP) scan-target resolution and the remote-error
// classifier — the core of broadening the scanner to streamable-http/sse
// servers (the bulk of the registry that npm-stdio can't reach).

import { describe, expect, it } from "vitest";
import { pickRemote, resolveScanTarget } from "../src/worker/install-resolver.js";
import { classifyRemoteError } from "../src/scanners/trust-scanner.js";

describe("pickRemote", () => {
  it("returns null for empty/missing remotes", () => {
    expect(pickRemote(null)).toBeNull();
    expect(pickRemote(undefined)).toBeNull();
    expect(pickRemote([])).toBeNull();
  });

  it("picks a streamable-http endpoint", () => {
    expect(pickRemote([{ url: "https://mcp.grafana.com/mcp", type: "streamable-http" }])).toEqual({
      kind: "http",
      url: "https://mcp.grafana.com/mcp",
      transport: "streamable-http",
    });
  });

  it("prefers streamable-http over legacy sse when both are present", () => {
    const got = pickRemote([
      { url: "https://mcp.alpic.ai/sse", type: "sse" },
      { url: "https://mcp.alpic.ai", type: "streamable-http" },
    ]);
    expect(got).toEqual({ kind: "http", url: "https://mcp.alpic.ai", transport: "streamable-http" });
  });

  it("falls back to sse when no streamable-http is offered", () => {
    expect(pickRemote([{ url: "https://api.agentrapay.ai/mcp", type: "sse" }])).toEqual({
      kind: "http",
      url: "https://api.agentrapay.ai/mcp",
      transport: "sse",
    });
  });

  it("ignores unknown transport types and non-http urls", () => {
    expect(pickRemote([{ url: "https://x.io/mcp", type: "websocket" }])).toBeNull();
    expect(pickRemote([{ url: "stdio://local", type: "streamable-http" }])).toBeNull();
  });
});

describe("resolveScanTarget", () => {
  const noNpm = async () => false;

  it("prefers a remote endpoint over an npm package (no sandbox risk)", async () => {
    const target = await resolveScanTarget(
      {
        source_url: "https://www.npmjs.com/package/some-pkg",
        remotes: [{ url: "https://mcp.example.com/mcp", type: "streamable-http" }],
      },
      noNpm,
    );
    expect(target).toEqual({
      kind: "http",
      url: "https://mcp.example.com/mcp",
      transport: "streamable-http",
    });
  });

  it("falls back to an npm stdio command when there is no remote", async () => {
    const target = await resolveScanTarget(
      { source_url: "https://www.npmjs.com/package/@scope/server", remotes: null },
      noNpm,
    );
    expect(target).toEqual({ kind: "stdio", command: "npx -y @scope/server" });
  });

  it("returns null when neither a remote nor an npm package resolves", async () => {
    const target = await resolveScanTarget(
      { source_url: "https://example.com/not-a-package", remotes: null },
      noNpm,
    );
    expect(target).toBeNull();
  });
});

describe("classifyRemoteError", () => {
  it("flags Cloudflare / bot challenges", () => {
    expect(classifyRemoteError(new Error("Just a moment... cf-ray 8xyz"))).toBe("challenge");
    expect(classifyRemoteError(new Error("Unexpected token '<', \"<!DOCTYPE html>\""))).toBe(
      "challenge",
    );
    expect(classifyRemoteError(new Error("Attention Required! | Cloudflare"))).toBe("challenge");
  });

  it("flags auth walls (401/403 and OAuth markers)", () => {
    expect(classifyRemoteError(Object.assign(new Error("nope"), { code: 401 }))).toBe("auth");
    expect(classifyRemoteError(new Error("HTTP 403 Forbidden"))).toBe("auth");
    expect(classifyRemoteError(new Error("WWW-Authenticate: Bearer"))).toBe("auth");
    expect(classifyRemoteError(new Error("Unauthorized"))).toBe("auth");
  });

  it("treats genuine connection failures as other", () => {
    expect(classifyRemoteError(new Error("getaddrinfo ENOTFOUND mcp.dead.io"))).toBe("other");
    expect(classifyRemoteError(Object.assign(new Error("server error"), { code: 503 }))).toBe(
      "other",
    );
    expect(classifyRemoteError(new Error("socket hang up"))).toBe("other");
  });
});
