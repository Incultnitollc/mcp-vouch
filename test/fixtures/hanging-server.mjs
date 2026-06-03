// Fake stdio MCP "server" that NEVER responds to `initialize`.
//
// Used by test/dispose.test.ts to verify TrustScanner.dispose() kills the
// spawned child after a timed-out scan (issue #1). Reads stdin to drain
// whatever the client sends and silently drops every byte — no JSON-RPC reply
// ever leaves stdout. A long-lived ref'd timer keeps the event loop alive even
// if stdin EOFs.
process.stdin.resume();
process.stdin.on("data", () => {});
process.stdin.on("end", () => {});
setInterval(() => {}, 60_000);
