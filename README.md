# MCP Vouch

Trust scoring and security layer for MCP servers.

Scans an MCP server against the OWASP MCP Top 10 and returns a **0–100 trust score** plus an **A–F grade**. The badge on the [MCP Registry](https://github.com/Incultnitollc/mcp-registry) listing is the product; the CLI is free and open.

## Install

```bash
npm install -g mcp-vouch
```

Or run without installing:

```bash
npx mcp-vouch scan "npx -y @modelcontextprotocol/server-everything"
```

## CLI

```bash
mcp-vouch scan <command> [--json] [--save <file>]
```

- `<command>` — full stdio launch command for the MCP server
- `--json` — print the raw `TrustReport` JSON instead of the colored report
- `--save <file>` — also write the JSON report to `<file>`

### Example: scan the reference server

```bash
$ mcp-vouch scan "npx -y @modelcontextprotocol/server-everything"

╔══════════════════════════════════╗
║     MCP Vouch — Trust Report     ║
╚══════════════════════════════════╝

Server:   mcp-servers/everything v2.0.0
Protocol: 2025-11-25
Duration: 2542ms

✅ PASS MCP01 Tool Poisoning                     10/10
⚠️ WARN MCP02 Insufficient Input Validation       5/10
✅ PASS MCP03 Resource Injection                 10/10
✅ PASS MCP04 Unauthorized Capability Exposure   10/10
⏭️ SKIP MCP05 Missing Authentication               -     (stdio: not applicable)
⏭️ SKIP MCP06 Insecure Transport                   -     (stdio: not applicable)
✅ PASS MCP07 Shadow Tool Registration           10/10
✅ PASS MCP08 Lack of Audit and Telemetry        10/10
⚠️ WARN MCP09 Inadequate Rate Limiting            5/10
⚠️ WARN MCP10 Supply Chain Risk                   5/10  (unpinned npx)

Trust Score: 81/100   Grade: B
```

HTTP-only checks (MCP05, MCP06) are SKIPPED for stdio servers and excluded from the score — we report what we actually tested.

## Library

```ts
import { scanServer, TrustScanner } from "mcp-vouch";
import type { TrustReport } from "mcp-vouch";

// One-shot helper
const report: TrustReport = await scanServer(
  "npx -y @modelcontextprotocol/server-everything",
);

// Or use the class directly for finer control
const scanner = new TrustScanner("npx -y @modelcontextprotocol/server-everything");
const report2 = await scanner.scan();
```

The library is what the MCP Registry scoring worker uses to score every listing on the registry.

## Badge

Once your server is listed on the [MCP Registry](https://github.com/Incultnitollc/mcp-registry), you can embed its live trust badge in your README:

```markdown
[![MCP Vouch](https://mcpvouch.com/api/badge/<server-slug>.svg)](https://mcp-registry-dh5.pages.dev/server/<server-slug>)
```

The badge renders the latest score + grade with the standard shields color scale (A green → F red) and links back to the full trust report on the registry. Updated automatically every 6 hours.

## What it checks

| # | Check | Applies to |
|---|---|---|
| MCP01 | Tool Poisoning | all |
| MCP02 | Insufficient Input Validation | all |
| MCP03 | Resource Injection | all |
| MCP04 | Unauthorized Capability Exposure | all |
| MCP05 | Missing Authentication | HTTP only |
| MCP06 | Insecure Transport | HTTP only |
| MCP07 | Shadow Tool Registration | all |
| MCP08 | Lack of Audit and Telemetry | all |
| MCP09 | Inadequate Rate Limiting | all |
| MCP10 | Supply Chain Risk | all |

`SKIP` checks (e.g. HTTP auth on a stdio server) are excluded from the score, not counted as failures. The score reflects what was actually tested.

## Status

- ✅ CLI + library shipping (`mcp-vouch` on npm)
- ✅ Live on every MCP Registry listing
- 🚧 Hosted dashboard + Verified badge tier — see [mcpvouch.com](https://mcpvouch.com)

## Part of the MCP ecosystem

- [MCP Probe](https://github.com/Incultnitollc/mcp-probe) — server testing CLI
- [MCP Registry](https://github.com/Incultnitollc/mcp-registry) — server discovery
- **MCP Vouch** — trust scoring (this repo)

## License

MIT
