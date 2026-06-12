// MCP Vouch worker — derive a runnable stdio command from a server row.
//
// This is the SANDBOX BOUNDARY (MAN-5 option (a)): we only ever run servers
// whose source_url resolves to an npm package, launched via `npx -y <pkg>`.
// Anything else returns null and the worker skips the scan.
//
// Logic is intentionally aligned with the MCP Registry's install-resolver
// (packages/cli/src/lib/install-resolver.ts). When the registry adds an
// `install_json` column at ingest (v1.2), this file can be deleted and the
// worker can read that column directly.
//
// Two surfaces resolve here:
//   - npm packages (source_url → `npx -y <pkg>`), the original sandbox path.
//   - remote HTTP endpoints (card_summary_json.remotes[] → an http ScanTarget),
//     which need no local launch and unlock the MCP05/MCP06 active checks.

import type { RemoteTransport, ScanTarget } from "../types/index.js";

export interface InstallBlock {
  command: string;
  args: string[];
  env: Record<string, string>;
}

export type ResolveSource = "npm-direct" | "npm-resolved" | "none";

export interface ResolveResult {
  block: InstallBlock | null;
  source: ResolveSource;
  packageName?: string;
}

export type NpmExists = (pkg: string) => Promise<boolean>;

const NPM_REGISTRY = "https://registry.npmjs.org";

function npxBlock(pkg: string): InstallBlock {
  return { command: "npx", args: ["-y", pkg], env: {} };
}

export function parseNpmPackage(sourceUrl: string): string | null {
  const m = sourceUrl.match(/npmjs\.com\/package\/(@[^/]+\/[^/?#]+|[^/?#]+)/i);
  return m ? decodeURIComponent(m[1]!) : null;
}

export function repoNameGuess(sourceUrl: string): string | null {
  const m = sourceUrl.match(/(?:github|gitlab)\.com\/[^/]+\/([^/?#]+)/i);
  if (!m) return null;
  return m[1]!.replace(/\.git$/i, "").toLowerCase();
}

/**
 * True only if the package has at least one published version on npm.
 * Hits `/<pkg>/latest` — 200 means a usable tag exists; 404 covers both
 * "package not found" and "package exists but never published a version"
 * (the ENOVERSIONS case that crashes `npx -y <pkg>` at runtime).
 */
export async function npmRegistryExists(pkg: string): Promise<boolean> {
  try {
    const res = await fetch(
      `${NPM_REGISTRY}/${pkg.replace("/", "%2F")}/latest`,
      { method: "GET" },
    );
    return res.ok;
  } catch {
    return false;
  }
}

export async function resolveInstall(
  sourceUrl: string | null,
  npmExists: NpmExists = npmRegistryExists,
): Promise<ResolveResult> {
  if (!sourceUrl) return { block: null, source: "none" };

  const npmPkg = parseNpmPackage(sourceUrl);
  if (npmPkg) {
    return { block: npxBlock(npmPkg), source: "npm-direct", packageName: npmPkg };
  }

  const guess = repoNameGuess(sourceUrl);
  if (guess && (await npmExists(guess))) {
    return { block: npxBlock(guess), source: "npm-resolved", packageName: guess };
  }

  return { block: null, source: "none" };
}

/** Render a resolved InstallBlock as a single stdio command string for scanServer(). */
export function blockToCommand(block: InstallBlock): string {
  return [block.command, ...block.args].join(" ");
}

// --- remote (HTTP) endpoints -------------------------------------------------

/** One entry of a registry server's `card_summary_json.remotes[]`. */
export interface RemoteEndpoint {
  url: string;
  /** "streamable-http" | "sse" (current spec) — anything else is ignored. */
  type: string;
}

function isHttpUrl(url: string | null | undefined): url is string {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

/**
 * Pick a connectable remote endpoint from a server's `remotes[]`, preferring the
 * current `streamable-http` transport over legacy `sse`. Returns null when the
 * server declares no usable HTTP remote. We connect unauthenticated — auth-gated
 * endpoints fail at handshake and the worker records that as skipped, not failed.
 */
export function pickRemote(
  remotes: RemoteEndpoint[] | null | undefined,
): Extract<ScanTarget, { kind: "http" }> | null {
  if (!remotes || remotes.length === 0) return null;
  const byType = (t: RemoteTransport) =>
    remotes.find((r) => r.type === t && isHttpUrl(r.url));
  const chosen = byType("streamable-http") ?? byType("sse");
  if (!chosen) return null;
  return {
    kind: "http",
    url: chosen.url,
    transport: chosen.type as RemoteTransport,
  };
}

/** Minimal view of a registry row needed to choose what to connect to. */
export interface ResolvableServer {
  source_url: string | null;
  remotes?: RemoteEndpoint[] | null;
}

/**
 * Choose the scan target for a registry server. A hosted remote endpoint is
 * preferred over an npm package: it needs no local launch (no OOM/sandbox risk)
 * and activates the auth + transport checks that stdio can only SKIP. Falls back
 * to the npm `npx -y <pkg>` stdio command, or null when neither resolves.
 */
export async function resolveScanTarget(
  server: ResolvableServer,
  npmExists: NpmExists = npmRegistryExists,
): Promise<ScanTarget | null> {
  const remote = pickRemote(server.remotes);
  if (remote) return remote;

  const npm = await resolveInstall(server.source_url, npmExists);
  if (npm.block) return { kind: "stdio", command: blockToCommand(npm.block) };
  return null;
}
