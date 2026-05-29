// MCP Vouch — terminal reporter
//
// Renders a TrustReport as a color-coded terminal report using chalk.

import chalk from "chalk";
import type { CheckResult, Grade, TrustReport } from "../types/index.js";

/** Per-status icon, label, and color. */
const STATUS_META: Record<
  CheckResult["status"],
  { icon: string; label: string; color: (s: string) => string }
> = {
  PASS: { icon: "✅", label: "PASS", color: chalk.green },
  FAIL: { icon: "❌", label: "FAIL", color: chalk.red },
  WARN: { icon: "⚠️", label: "WARN", color: chalk.yellow },
  SKIP: { icon: "⏭️", label: "SKIP", color: chalk.gray },
};

/** Color for the final grade, by band. */
function gradeColor(grade: Grade): (s: string) => string {
  switch (grade) {
    case "A":
      return chalk.greenBright;
    case "B":
      return chalk.green;
    case "C":
      return chalk.yellow;
    case "D":
      return chalk.red;
    case "F":
      return chalk.redBright;
  }
}

function renderCheck(c: CheckResult): string {
  const meta = STATUS_META[c.status];
  const score = c.status === "SKIP" ? "  -  " : `${c.score}/10`;
  const line =
    `${meta.icon} ${meta.color(meta.label.padEnd(4))} ` +
    `${chalk.bold(c.id)} ${c.name.padEnd(34)} ` +
    `${meta.color(score.padStart(5))}  ${chalk.gray(`(${c.duration}ms)`)}`;
  // Show the explanation for everything except clean passes — those are the
  // actionable findings a publisher needs to read.
  if (c.status === "PASS") return line;
  return `${line}\n   ${chalk.gray(c.details)}`;
}

/** Build the full report as a string (useful for testing). */
export function renderReport(report: TrustReport): string {
  const { serverInfo: s } = report;
  const gc = gradeColor(report.grade);
  const rule = chalk.gray("━".repeat(50));

  return [
    chalk.cyan("╔══════════════════════════════════╗"),
    chalk.cyan("║     MCP Vouch — Trust Report     ║"),
    chalk.cyan("╚══════════════════════════════════╝"),
    "",
    `${chalk.bold("Server:")}   ${s.name} v${s.version}`,
    `${chalk.bold("Protocol:")} ${s.protocolVersion}`,
    `${chalk.bold("Scanned:")}  ${report.scannedAt}`,
    `${chalk.bold("Duration:")} ${report.duration}ms`,
    "",
    ...report.checks.map(renderCheck),
    "",
    rule,
    `${chalk.bold("Trust Score:")} ${gc(`${report.totalScore}/100`)}   ` +
      `${chalk.bold("Grade:")} ${gc(chalk.bold(report.grade))}`,
    rule,
  ].join("\n");
}

/** Print the full color-coded report to stdout. */
export function printReport(report: TrustReport): void {
  console.log(renderReport(report));
}
