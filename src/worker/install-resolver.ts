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

export async function npmRegistryExists(pkg: string): Promise<boolean> {
  try {
    const res = await fetch(`${NPM_REGISTRY}/${pkg.replace("/", "%2F")}`, {
      method: "GET",
    });
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
