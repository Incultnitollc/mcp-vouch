// Sandbox-boundary tests for the worker's install resolver. The resolver is
// what stands between an arbitrary registry row and `npx -y <something>` on
// our worker — it must reject everything that isn't an npm-published package.

import { describe, expect, it } from "vitest";
import {
  blockToCommand,
  parseNpmPackage,
  repoNameGuess,
  resolveInstall,
} from "../src/worker/install-resolver.js";

describe("parseNpmPackage", () => {
  it("parses an unscoped npm package URL", () => {
    expect(parseNpmPackage("https://www.npmjs.com/package/foo")).toBe("foo");
  });

  it("parses a scoped npm package URL", () => {
    expect(parseNpmPackage("https://www.npmjs.com/package/@modelcontextprotocol/sdk")).toBe(
      "@modelcontextprotocol/sdk",
    );
  });

  it("returns null for a github URL", () => {
    expect(parseNpmPackage("https://github.com/foo/bar")).toBeNull();
  });
});

describe("repoNameGuess", () => {
  it("derives a lowercase package name from a github repo URL", () => {
    expect(repoNameGuess("https://github.com/Foo/Bar")).toBe("bar");
  });

  it("strips a trailing .git", () => {
    expect(repoNameGuess("https://github.com/foo/bar.git")).toBe("bar");
  });

  it("returns null for non-git host URLs", () => {
    expect(repoNameGuess("https://example.com/foo")).toBeNull();
  });
});

describe("resolveInstall (sandbox boundary)", () => {
  const npmExistsStub = (allow: Set<string>) => async (pkg: string) => allow.has(pkg);

  it("resolves a direct npm URL to an npx block", async () => {
    const r = await resolveInstall(
      "https://www.npmjs.com/package/@modelcontextprotocol/server-everything",
      npmExistsStub(new Set()),
    );
    expect(r.source).toBe("npm-direct");
    expect(r.block).toEqual({
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-everything"],
      env: {},
    });
  });

  it("resolves a github URL only if the guessed package exists on npm", async () => {
    const r = await resolveInstall(
      "https://github.com/foo/server-everything",
      npmExistsStub(new Set(["server-everything"])),
    );
    expect(r.source).toBe("npm-resolved");
    expect(r.packageName).toBe("server-everything");
  });

  it("returns no block when the github guess is not on npm — DOES NOT execute", async () => {
    const r = await resolveInstall(
      "https://github.com/foo/totally-not-on-npm",
      npmExistsStub(new Set()),
    );
    expect(r.block).toBeNull();
    expect(r.source).toBe("none");
  });

  it("returns no block for a null source_url", async () => {
    const r = await resolveInstall(null);
    expect(r.block).toBeNull();
    expect(r.source).toBe("none");
  });

  it("returns no block for an unknown host (pypi, raw URL, etc.)", async () => {
    const r = await resolveInstall("https://pypi.org/project/something/", npmExistsStub(new Set()));
    expect(r.block).toBeNull();
    expect(r.source).toBe("none");
  });
});

describe("blockToCommand", () => {
  it("renders an InstallBlock as a single stdio command string", () => {
    expect(
      blockToCommand({ command: "npx", args: ["-y", "@scope/pkg"], env: {} }),
    ).toBe("npx -y @scope/pkg");
  });
});
