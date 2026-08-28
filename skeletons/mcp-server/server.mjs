// server.mjs — netwatch stdio MCP server (DECISIONS.md D6).
// Runs under the official nodejs node.exe as a child of the Tier-2 claude
// process (--mcp-config + --strict-mcp-config).
// Every tool shells out to a fixed .ps1 via `pwsh -File` (never -Command:
// GOAL rule about cross-shell escaping) and relays the script's JSON stdout.
// The tool scripts own all validation/guards; this server adds only:
// schema-typed inputs, a 20 s per-call timeout, and kill on timeout.

// SDK v2 API (verified against modelcontextprotocol/typescript-sdk README, 2026-08-26)
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const TOOLS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "tools");
// pwsh 7 ONLY (machine rule: PS 5.1 silently breaks Get-AuthenticodeSignature).
// Full path injected by Tier 1 via mcp-config env; must point at PowerShell 7.
const PWSH = process.env.NETWATCH_PWSH ?? "pwsh.exe";
const TIMEOUT_MS = 20_000;

function runTool(script, args) {
  return new Promise((resolve) => {
    execFile(
      PWSH,
      ["-NoProfile", "-File", path.join(TOOLS_DIR, script), ...args],
      { timeout: TIMEOUT_MS, killSignal: "SIGKILL", windowsHide: true },
      (err, stdout) => {
        if (err && !stdout) {
          resolve(JSON.stringify({ error: "tool_failed", detail: String(err.code ?? err.message) }));
        } else {
          resolve(stdout.trim()); // scripts always emit a single JSON object
        }
      }
    );
  });
}

const server = new McpServer({ name: "netwatch", version: "1.0.0" });
const asText = (s) => ({ content: [{ type: "text", text: s }] });

server.registerTool("check_signature",
  { description: "Authenticode signature of a file (read-only). NotSigned with msix_context=true is expected for MSIX/AppX apps.",
    inputSchema: z.object({ path: z.string().describe("absolute file path") }) },
  async ({ path: p }) => asText(await runTool("check-signature.ps1", ["-Path", p])));

server.registerTool("hash_file",
  { description: "SHA256 + size + mtime of a file (read-only).",
    inputSchema: z.object({ path: z.string().describe("absolute file path") }) },
  async ({ path: p }) => asText(await runTool("hash-file.ps1", ["-Path", p])));

server.registerTool("check_reputation",
  { description: "AbuseIPDB/VirusTotal reputation for a public IP. Refuses private/CGNAT/own IPs (refusal is final). quota_exhausted is not evidence.",
    inputSchema: z.object({ ip: z.string().describe("IP literal") }) },
  async ({ ip }) => asText(await runTool("check-reputation.ps1", ["-Ip", ip])));

server.registerTool("check_process_lineage",
  { description: "Parent-process chain for a PID (read-only, root-first). alive=false when the process already exited.",
    inputSchema: z.object({ pid: z.number().int().describe("process id") }) },
  async ({ pid }) => asText(await runTool("check-process-lineage.ps1", ["-ProcessId", String(pid)])));

await server.connect(new StdioServerTransport());
