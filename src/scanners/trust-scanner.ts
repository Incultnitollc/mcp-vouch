// MCP Vouch — core trust scanner
//
// Connects to an MCP server over stdio using the official SDK, runs the 10
// OWASP MCP Top 10 checks sequentially, and returns a TrustReport.
//
// Design honesty: several OWASP MCP risks (auth, transport security) only apply
// to servers exposed over HTTP. When scanning a local stdio server those checks
// return SKIP and are excluded from the score, rather than being faked as PASS.
// Each check's `details` states exactly what was tested and what its limits are.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  CheckResult,
  Grade,
  ScanTarget,
  ServerInfo,
  TrustReport,
} from "../types/index.js";
import { MAX_POINTS_PER_CHECK } from "../types/index.js";

/**
 * Why a remote (HTTP) handshake failed, distinguished from a genuine error so
 * the worker can record it as a SKIP (not a failure) and avoid alert fatigue:
 *   - "auth": endpoint requires authentication we don't have (401, or 403 with
 *     OAuth/WWW-Authenticate markers). Honest: we couldn't inspect it.
 *   - "challenge": a bot-protection wall (Cloudflare "just a moment", cf-ray,
 *     or an HTML body where MCP JSON was expected). Not the server's fault line.
 *   - "other": real connection failure (DNS, 5xx, timeout) — counts as failed.
 */
export type RemoteErrorKind = "auth" | "challenge" | "other";

export function classifyRemoteError(err: unknown): RemoteErrorKind {
  const message = (err instanceof Error ? err.message : String(err)).toLowerCase();
  const code = typeof (err as { code?: unknown })?.code === "number"
    ? (err as { code: number }).code
    : undefined;

  // Cloudflare / bot-wall: HTML where JSON/SSE was expected, or explicit markers.
  if (
    /just a moment|cf-ray|cloudflare|attention required|checking your browser|enable javascript/.test(
      message,
    ) ||
    /unexpected token '?<|<!doctype|<html/.test(message)
  ) {
    return "challenge";
  }

  // Authentication required.
  if (
    code === 401 ||
    /\b401\b|unauthorized|www-authenticate|authentication required|invalid token|oauth/.test(
      message,
    )
  ) {
    return "auth";
  }
  // A bare 403 with no CF markers is most often an auth/permission gate.
  if (code === 403 || /\b403\b|forbidden/.test(message)) return "auth";

  return "other";
}

/** Patterns that suggest a tool description is trying to inject instructions. */
const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+|the\s+)?(previous|prior|above)/i,
  /disregard\s+(all\s+|the\s+)?(previous|prior|above|instructions)/i,
  /system\s+prompt/i,
  /you\s+are\s+now/i,
  /do\s+not\s+(tell|inform|reveal|mention)/i,
  /<important>|<secret>|<system>/i,
  /override\s+(the\s+)?(instructions|rules)/i,
  /act\s+as\s+(if|though)/i,
];

/** Verbs that indicate a tool can take dangerous, high-impact actions. */
const DANGEROUS_PATTERNS: RegExp[] = [
  /\b(exec|eval|spawn|shell|bash|sh)\b/i,
  /\b(rm|delete|destroy|drop|truncate|unlink)\b/i,
  /\bsudo\b/i,
  /\b(write[_-]?file|run[_-]?command|system[_-]?call)\b/i,
];

/** Names that a malicious server might shadow to hijack trusted behavior. */
const SHADOW_TARGETS = new Set([
  "search",
  "fetch",
  "read_file",
  "write_file",
  "list_files",
  "execute",
  "run",
]);

export class TrustScanner {
  private readonly target: ScanTarget;
  private client: Client | null = null;
  private serverInfo: ServerInfo = {
    name: "unknown",
    version: "unknown",
    protocolVersion: "unknown",
  };

  /**
   * @param target Either a stdio launch command string (back-compat — e.g.
   *   `"npx -y @modelcontextprotocol/server-everything"`), or a {@link ScanTarget}
   *   (stdio with extra env, or an `http` remote endpoint).
   * @param extraEnv Extra env vars merged into the spawned stdio child on top of
   *   the SDK's safe-inherit defaults (e.g. NPM_CONFIG_IGNORE_SCRIPTS). Must be
   *   passed via the transport because the SDK spawns with a sanitized env
   *   safelist, not the parent's full environment. Ignored for http targets.
   */
  constructor(target: string | ScanTarget, extraEnv: Record<string, string> = {}) {
    if (typeof target === "string") {
      this.target = { kind: "stdio", command: target.trim(), extraEnv };
    } else if (target.kind === "stdio") {
      this.target = {
        kind: "stdio",
        command: target.command.trim(),
        extraEnv: { ...target.extraEnv, ...extraEnv },
      };
    } else {
      this.target = target;
    }
  }

  /** Connect, run all 10 checks, disconnect, and return the report. */
  async scan(): Promise<TrustReport> {
    const start = Date.now();
    await this.connect();

    const checks: CheckResult[] = [];
    // Sequential — all checks share the single connected client.
    checks.push(await this.timed("MCP01", "Tool Poisoning", () => this.checkToolPoisoning()));
    checks.push(await this.timed("MCP02", "Insufficient Input Validation", () => this.checkInputValidation()));
    checks.push(await this.timed("MCP03", "Resource Injection", () => this.checkResourceInjection()));
    checks.push(await this.timed("MCP04", "Unauthorized Capability Exposure", () => this.checkCapabilityExposure()));
    checks.push(await this.timed("MCP05", "Missing Authentication", () => this.checkAuthentication()));
    checks.push(await this.timed("MCP06", "Insecure Transport", () => this.checkTransport()));
    checks.push(await this.timed("MCP07", "Shadow Tool Registration", () => this.checkShadowTools()));
    checks.push(await this.timed("MCP08", "Lack of Audit and Telemetry", () => this.checkAuditTelemetry()));
    checks.push(await this.timed("MCP09", "Inadequate Rate Limiting", () => this.checkRateLimiting()));
    checks.push(await this.timed("MCP10", "Supply Chain Risk", () => this.checkSupplyChain()));

    await this.disconnect();

    const totalScore = this.computeTotalScore(checks);
    return {
      totalScore,
      grade: this.toGrade(totalScore),
      checks,
      serverInfo: this.serverInfo,
      scannedAt: new Date().toISOString(),
      duration: Date.now() - start,
    };
  }

  // --- connection -----------------------------------------------------------

  private async connect(): Promise<void> {
    const transport =
      this.target.kind === "http"
        ? this.makeHttpTransport(this.target)
        : this.makeStdioTransport(this.target);

    // The SDK reports the negotiated protocol version by calling the transport's
    // optional `setProtocolVersion` hook during initialize. The transports don't
    // store it, so we attach our own hook to capture it cleanly.
    let protocolVersion = "unknown";
    (transport as { setProtocolVersion?: (v: string) => void }).setProtocolVersion =
      (v: string) => {
        protocolVersion = v;
      };

    this.client = new Client(
      { name: "mcp-vouch", version: "0.1.0" },
      { capabilities: {} },
    );
    await this.client.connect(transport);

    const impl = this.client.getServerVersion();
    this.serverInfo = {
      name: impl?.name ?? "unknown",
      version: impl?.version ?? "unknown",
      protocolVersion,
    };
  }

  private makeStdioTransport(target: Extract<ScanTarget, { kind: "stdio" }>): Transport {
    const parts = target.command.split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
      throw new Error("Empty server command.");
    }
    const [cmd, ...args] = parts;
    const extraEnv = target.extraEnv ?? {};
    // The SDK merges this `env` with its safe-inherit defaults (HOME/PATH/…),
    // so extraEnv (e.g. NPM_CONFIG_IGNORE_SCRIPTS) reaches the `npx` child even
    // though the parent's full environment is intentionally not forwarded.
    return new StdioClientTransport({
      command: cmd!,
      args,
      ...(Object.keys(extraEnv).length > 0 ? { env: extraEnv } : {}),
    });
  }

  private makeHttpTransport(target: Extract<ScanTarget, { kind: "http" }>): Transport {
    // Connect unauthenticated. Auth-gated endpoints reject the handshake; the
    // worker classifies that (classifyRemoteError) as a skip, not a failure.
    const url = new URL(target.url);
    return target.transport === "sse"
      ? new SSEClientTransport(url)
      : new StreamableHTTPClientTransport(url);
  }

  private async disconnect(): Promise<void> {
    try {
      await this.client?.close();
    } catch {
      // ignore close errors
    }
    this.client = null;
  }

  /**
   * Force-release the underlying client and transport (kills the spawned stdio
   * child). Safe to call from outside after a timed-out or failed scan — the
   * worker uses this to prevent orphan `npx` processes from holding RSS. Idempotent.
   */
  async dispose(): Promise<void> {
    await this.disconnect();
  }

  private requireClient(): Client {
    if (!this.client) throw new Error("Not connected.");
    return this.client;
  }

  // --- check helpers --------------------------------------------------------

  /** Time a check and convert thrown errors into a SKIP result. */
  private async timed(
    id: string,
    name: string,
    fn: () => Promise<Omit<CheckResult, "id" | "name" | "duration">>,
  ): Promise<CheckResult> {
    const start = Date.now();
    try {
      const partial = await fn();
      return { id, name, ...partial, duration: Date.now() - start };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        id,
        name,
        status: "SKIP",
        score: 0,
        details: `Check could not run: ${message}`,
        duration: Date.now() - start,
      };
    }
  }

  private async safeListTools() {
    try {
      const res = await this.requireClient().listTools();
      return res.tools ?? [];
    } catch {
      return [];
    }
  }

  // --- the 10 checks --------------------------------------------------------

  // MCP01 — Tool Poisoning: do tool descriptions try to inject instructions?
  private async checkToolPoisoning(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const tools = await this.safeListTools();
    if (tools.length === 0) {
      return { status: "SKIP", score: 0, details: "Server exposes no tools to inspect." };
    }
    const flagged: string[] = [];
    for (const tool of tools) {
      const haystack = `${tool.name} ${tool.description ?? ""} ${JSON.stringify(tool.inputSchema ?? {})}`;
      if (INJECTION_PATTERNS.some((re) => re.test(haystack))) flagged.push(tool.name);
    }
    if (flagged.length === 0) {
      return {
        status: "PASS",
        score: 10,
        details: `Scanned ${tools.length} tool description(s) for prompt-injection patterns; none found.`,
      };
    }
    return {
      status: "FAIL",
      score: 0,
      details: `Possible prompt-injection in tool description(s): ${flagged.join(", ")}.`,
    };
  }

  // MCP02 — Input Validation: does the server reject malformed tool input gracefully?
  private async checkInputValidation(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const tools = await this.safeListTools();
    if (tools.length === 0) {
      return { status: "SKIP", score: 0, details: "No tools available to test input validation." };
    }
    // Prefer a tool whose name looks read-only / side-effect-free.
    const safe = tools.find((t) => /echo|get|list|read|ping|add|sum|describe/i.test(t.name)) ?? tools[0];
    try {
      // Deliberately malformed: a property the schema is unlikely to accept.
      await this.requireClient().callTool({
        name: safe.name,
        arguments: { __mcp_signal_invalid__: "💥".repeat(64) },
      });
      // It accepted clearly-invalid input without error → weak validation.
      return {
        status: "WARN",
        score: 5,
        details: `Tool "${safe.name}" accepted clearly-invalid arguments without raising an error. Validate inputs against the schema and reject unknown fields.`,
      };
    } catch {
      // Rejecting malformed input is the correct, secure behavior.
      return {
        status: "PASS",
        score: 10,
        details: `Tool "${safe.name}" rejected malformed input with an error (graceful validation).`,
      };
    }
  }

  // MCP03 — Resource Injection: do resource URIs allow path traversal?
  private async checkResourceInjection(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const client = this.requireClient();
    let resources: { uri: string }[] = [];
    let templates: { uriTemplate: string }[] = [];
    try {
      resources = (await client.listResources()).resources ?? [];
    } catch {
      /* server may not support resources */
    }
    try {
      templates = (await client.listResourceTemplates()).resourceTemplates ?? [];
    } catch {
      /* server may not support resource templates */
    }
    if (resources.length === 0 && templates.length === 0) {
      return { status: "SKIP", score: 0, details: "Server exposes no resources or templates to test." };
    }
    // Attempt a path-traversal read against a likely file-backed scheme.
    const traversal = "file:///../../../../../../etc/passwd";
    try {
      const res = await client.readResource({ uri: traversal });
      const text = JSON.stringify(res).toLowerCase();
      if (text.includes("root:") || text.includes("/bin/")) {
        return {
          status: "FAIL",
          score: 0,
          details: `Path-traversal URI "${traversal}" returned system file contents. Reject ".." segments and canonicalize resource paths.`,
        };
      }
      return {
        status: "WARN",
        score: 6,
        details: `Path-traversal URI was accepted (no error) but did not return obvious system files. Confirm the server canonicalizes and sandboxes resource paths.`,
      };
    } catch {
      return {
        status: "PASS",
        score: 10,
        details: `Path-traversal resource URI was rejected. ${resources.length} resource(s), ${templates.length} template(s) present.`,
      };
    }
  }

  // MCP04 — Unauthorized Capability Exposure: are dangerous tools exposed?
  private async checkCapabilityExposure(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const tools = await this.safeListTools();
    if (tools.length === 0) {
      return { status: "SKIP", score: 0, details: "No tools exposed." };
    }
    const dangerous = tools
      .filter((t) => DANGEROUS_PATTERNS.some((re) => re.test(`${t.name} ${t.description ?? ""}`)))
      .map((t) => t.name);
    if (dangerous.length === 0) {
      return {
        status: "PASS",
        score: 10,
        details: `No high-impact tools (exec/shell/delete/file-write) detected among ${tools.length} tool(s).`,
      };
    }
    return {
      status: "WARN",
      score: 4,
      details: `High-impact tool(s) exposed: ${dangerous.join(", ")}. Ensure these require explicit authorization and confirmation before use.`,
    };
  }

  // MCP05 — Missing Authentication: only meaningful for network-exposed servers.
  private async checkAuthentication(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    if (this.target.kind !== "http") {
      return {
        status: "SKIP",
        score: 0,
        details:
          "Scanned over local stdio, where authentication is not applicable (the client owns the process). This check is active when scanning an HTTP/SSE endpoint.",
      };
    }
    // We reached the checks, so the server completed an MCP handshake for an
    // unauthenticated client. Auth-required endpoints reject before this point
    // (the worker records them as skipped, not scored). A public endpoint isn't
    // automatically wrong, but a network-exposed MCP server that needs no auth
    // to initialize and list tools is a real exposure worth flagging.
    return {
      status: "WARN",
      score: 5,
      details:
        "Server accepted an unauthenticated MCP session over the network (no credentials supplied). Network-exposed endpoints should require authentication (e.g. OAuth/bearer) and gate every tool call server-side. Confirm sensitive tools aren't reachable anonymously.",
    };
  }

  // MCP06 — Insecure Transport: only meaningful for HTTP transport.
  private async checkTransport(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    if (this.target.kind !== "http") {
      return {
        status: "SKIP",
        score: 0,
        details:
          "Transport is local stdio; HTTP-specific protections (TLS, Host-header validation, origin checks) do not apply. This check is active when scanning an HTTP/SSE endpoint.",
      };
    }
    if (!/^https:\/\//i.test(this.target.url)) {
      return {
        status: "FAIL",
        score: 0,
        details:
          "Endpoint is served over plaintext http:// — all traffic, including any bearer tokens and tool arguments, is unencrypted and tamperable on the wire. Serve over https:// with a valid TLS certificate.",
      };
    }
    return {
      status: "PASS",
      score: 10,
      details: `Endpoint is served over TLS (https) via the ${this.target.transport} transport. Transport-level confidentiality and integrity are in place.`,
    };
  }

  // MCP07 — Shadow Tool Registration: duplicate or trusted-name-shadowing tools.
  private async checkShadowTools(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const tools = await this.safeListTools();
    if (tools.length === 0) {
      return { status: "SKIP", score: 0, details: "No tools exposed." };
    }
    const seen = new Set<string>();
    const duplicates: string[] = [];
    const shadows: string[] = [];
    for (const tool of tools) {
      const lower = tool.name.toLowerCase();
      if (seen.has(lower)) duplicates.push(tool.name);
      seen.add(lower);
      if (SHADOW_TARGETS.has(lower)) shadows.push(tool.name);
    }
    if (duplicates.length === 0 && shadows.length === 0) {
      return {
        status: "PASS",
        score: 10,
        details: `All ${tools.length} tool name(s) are unique and none shadow well-known trusted tool names.`,
      };
    }
    const notes: string[] = [];
    if (duplicates.length) notes.push(`duplicate names: ${duplicates.join(", ")}`);
    if (shadows.length) notes.push(`shadows trusted names: ${shadows.join(", ")}`);
    return {
      status: "WARN",
      score: 5,
      details: `Potential shadowing detected (${notes.join("; ")}). Namespace tools to avoid collisions with trusted tools.`,
    };
  }

  // MCP08 — Audit/Telemetry: does the server declare a logging capability?
  private async checkAuditTelemetry(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const caps = this.requireClient().getServerCapabilities();
    if (caps && "logging" in caps && caps.logging) {
      return {
        status: "PASS",
        score: 10,
        details: "Server declares the `logging` capability, enabling audit/telemetry of activity.",
      };
    }
    return {
      status: "WARN",
      score: 5,
      details:
        "Server does not declare a `logging` capability. Without server-side logging, security-relevant activity cannot be audited.",
    };
  }

  // MCP09 — Rate Limiting: do rapid repeated requests get throttled?
  private async checkRateLimiting(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    const client = this.requireClient();
    const N = 20;
    let rejected = 0;
    for (let i = 0; i < N; i++) {
      try {
        await client.listTools();
      } catch {
        rejected++;
      }
    }
    if (rejected > 0) {
      return {
        status: "PASS",
        score: 10,
        details: `${rejected}/${N} rapid requests were rejected — some throttling/limiting is present.`,
      };
    }
    return {
      status: "WARN",
      score: 5,
      details: `All ${N} rapid requests succeeded with no throttling. Local stdio rarely rate-limits; this matters most for hosted/HTTP deployments.`,
    };
  }

  // MCP10 — Supply Chain Risk: is the server package version-pinned?
  private async checkSupplyChain(): Promise<Omit<CheckResult, "id" | "name" | "duration">> {
    if (this.target.kind === "http") {
      return {
        status: "WARN",
        score: 6,
        details:
          "Remote hosted endpoint: you depend on the operator's live deployment, which can be updated at any time and isn't version-pinnable from the registry. Supply-chain trust here rests on the operator's release and infrastructure practices rather than a pinned package.",
      };
    }
    const cmd = this.target.command;
    const isNpx = /\bnpx\b/.test(cmd);
    // Look for a pinned version like "pkg@1.2.3" anywhere in the command.
    const pinned = /@\d+\.\d+\.\d+/.test(cmd);
    if (isNpx && !pinned) {
      return {
        status: "WARN",
        score: 5,
        details:
          "Server is launched via `npx` without a pinned version (resolves to latest). An attacker who publishes a malicious version would be pulled in automatically. Pin an exact version (pkg@x.y.z) or vendor the dependency.",
      };
    }
    if (pinned) {
      return {
        status: "PASS",
        score: 8,
        details:
          "Server command pins an exact package version, reducing supply-chain risk. (Deep dependency auditing is out of scope for this check.)",
      };
    }
    return {
      status: "WARN",
      score: 6,
      details:
        "Could not determine package pinning from the command. Verify the server and its dependencies come from trusted, version-pinned sources.",
    };
  }

  // --- scoring --------------------------------------------------------------

  /** Sum awarded points over applicable (non-SKIP) checks, scaled to 0–100. */
  private computeTotalScore(checks: CheckResult[]): number {
    const scored = checks.filter((c) => c.status !== "SKIP");
    if (scored.length === 0) return 0;
    const earned = scored.reduce((sum, c) => sum + c.score, 0);
    const possible = scored.length * MAX_POINTS_PER_CHECK;
    return Math.round((earned / possible) * 100);
  }

  private toGrade(score: number): Grade {
    if (score >= 90) return "A";
    if (score >= 75) return "B";
    if (score >= 60) return "C";
    if (score >= 40) return "D";
    return "F";
  }
}
