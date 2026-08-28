// mcp-client.mjs - minimal stdio MCP test client (newline-delimited JSON-RPC).
// Usage: node mcp-client.mjs <server.mjs> list
//        node mcp-client.mjs <server.mjs> call <tool> <json-args>
// Prints the result (tool names or first text content) as JSON on stdout.
// Env is passed through to the server child (NETWATCH_* overrides).

import { spawn } from "node:child_process";
import process from "node:process";

const [serverPath, mode, toolName, jsonArgs] = process.argv.slice(2);
if (!serverPath || !mode) {
  console.error("usage: mcp-client.mjs <server.mjs> list|call [tool] [json-args]");
  process.exit(2);
}

const child = spawn(process.execPath, [serverPath], {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
});

let buffer = "";
const pending = new Map();
let nextId = 1;

child.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    }
  }
});

function request(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => {
      if (pending.has(id)) { pending.delete(id); reject(new Error(`timeout waiting for ${method}`)); }
    }, 30_000);
  });
}

function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

try {
  const init = await request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "netwatch-test-client", version: "0.0.1" },
  });
  notify("notifications/initialized", {});

  if (mode === "list") {
    const res = await request("tools/list", {});
    console.log(JSON.stringify({
      server: init.serverInfo?.name,
      tools: res.tools.map((t) => t.name).sort(),
    }));
  } else if (mode === "call") {
    const res = await request("tools/call", {
      name: toolName,
      arguments: JSON.parse(jsonArgs ?? "{}"),
    });
    const text = res.content?.find((c) => c.type === "text")?.text ?? "";
    console.log(JSON.stringify({ isError: res.isError ?? false, text }));
  } else {
    throw new Error(`unknown mode ${mode}`);
  }
  process.exit(0);
} catch (e) {
  console.error(String(e.message ?? e));
  process.exit(1);
} finally {
  child.kill();
}
