#!/usr/bin/env node
// MCP Vouch - Trust scoring for MCP servers
import { Command } from "commander";
import { writeFileSync } from "node:fs";
import { TrustScanner } from "./scanners/trust-scanner.js";
import { printReport } from "./reporters/terminal.js";

const program = new Command();

program
  .name("mcp-vouch")
  .description("Trust scoring and security layer for MCP servers")
  .version("0.1.0");

program
  .command("scan")
  .argument("<command>", "command that launches the MCP server (e.g. \"npx -y @modelcontextprotocol/server-everything\")")
  .option("--json", "output the raw JSON report")
  .option("--save", "save the JSON report to mcp-vouch-report.json")
  .action(async (command: string, opts: { json?: boolean; save?: boolean }) => {
    const scanner = new TrustScanner(command);
    const report = await scanner.scan();

    if (opts.save) {
      writeFileSync("mcp-vouch-report.json", JSON.stringify(report, null, 2));
    }
    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    printReport(report);
  });

program.parseAsync();
