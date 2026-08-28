# Tier-2 Contract: tool surface, invocation, verdict

Tier 2 is a headless `claude` (model sonnet) run whose ONLY capabilities
are four read-only MCP tools. Containment principle: destructive capability
does not exist anywhere in the surface; a permission filter over an open
shell was explicitly rejected in the GOAL (alias/IEX/reflection bypasses).

## 0. Cost model (clarified 2026-08-28)

Tier 2 runs on the operator's claude.ai **subscription via OAuth token**.
The `cost_usd` field in `*-stdout.json` envelopes is an API-equivalent
estimate for accounting, NOT a real charge. The binding constraint is the
subscription **session quota**: observed live on 2026-08-28, when HTTP 429
"session limit" killed both Tier-2 attempts of two alarms (reason
`tier2_failed` = analyzer never ran, not a finding). That quota is SHARED
with the operator's interactive claude windows. Hence the standing rule:
live Tier-2 runs outside the monitor's own escalation flow need the
operator's go — for quota, not for dollars. The reputation-API quotas
(AbuseIPDB/VT, `state/repquota.json`) are real external limits and
unrelated to this.

## 1. Tool surface (MCP server `netwatch`, stdio, Node)

Tool names as seen by the model: `mcp__netwatch__<tool>`.
Every tool: read-only, argument-validated, per-call timeout 20 s, returns
JSON text content. Common hard denials inside every tool (enforced in the
.ps1, regardless of what the model asks): any path under
`C:\Users\YOURNAME\Downloads`; any write/modify/delete operation (none exist
in the scripts at all).

### 1.1 `check_signature`
- Input: `{ "path": "<absolute file path>" }`
- Validation: absolute path, file exists, not under Downloads.
- Action: `pwsh -File check-signature.ps1 <path>` ->
  `Get-AuthenticodeSignature` (pwsh 7 mandatory — the PS 5.1 silent-fail
  bug is exactly here) + signer chain subjects + timestamp.
- Output: `{ status, signer_chain[], is_os_binary, msix_context }`.
  `msix_context: true` when the path is under `WindowsApps`/an MSIX
  package root — the prompt tells the model `NotSigned` is EXPECTED there
  (package-signed, not Authenticode-signed; GOAL baseline).

### 1.2 `hash_file`
- Input: `{ "path": "<absolute file path>" }`
- Action: SHA256 (`Get-FileHash`) + file size + last-write time.
- Output: `{ sha256, size_bytes, last_write_utc }`. The model may quote
  the hash in its verdict for Tier-3 to compare against upstream; Tier 2
  itself has no web access — by design, hash *comparison* against vendor
  sources is Tier-3 human-supervised work.

### 1.3 `check_reputation`
- Input: `{ "ip": "<literal IPv4/IPv6>" }`
- Validation + hard guards (defense in depth, duplicated from Tier 1):
  refuses (returns `{ "refused": "<reason>" }`, not an error) — own public
  IP (reads `state/ownip.json`: detected + last-known + recorded static
  `203.0.113.10`), RFC1918, 100.64.0.0/10, loopback, link-local,
  multicast/reserved. This guard is not model-overridable.
- Action: AbuseIPDB check + VirusTotal ip-address lookup, through the
  quota ledger `state/repquota.json` (VT budget: <= 400/day and 4/min kept
  under the ~500/day free tier; AbuseIPDB analogous). Keys from MCP-server
  env (set by Tier 1 from DPAPI-protected `state/apikeys.dat`), never in
  prompt/log.
- Output: `{ abuseipdb: {score, reports, last_seen}, virustotal:
  {malicious, suspicious, harmless}, quota: {vt_remaining_today, ...} }`
  or `{ quota_exhausted: true }` — prompt instructs: quota exhaustion is
  not evidence, proceed on other checks.

### 1.4 `check_process_lineage`
- Input: `{ "pid": <int> }`
- Action: CIM `Win32_Process` walk pid -> parent -> ... (max depth 10,
  cycle-guarded): per hop `{ pid, name, exe_path, exe_path_source,
  command_line, command_line_source, start_time, parent_pid }`.
  `Win32_Process` reads `exe_path` and `command_line` from the target's PEB,
  which is unreadable for PPL/protected processes (Defender, and some SYSTEM
  services); those fall back to the kernel's own records
  (`QueryFullProcessImageName`, `NtQueryInformationProcess`) — but the
  fallback answers only when the runner's privileges allow opening the
  target (probed 2026-08-27: the open is ACCESS_DENIED against the PPL
  antimalware set for an ordinary user). The `*_source` fields say which
  record answered: `wmi` | `kernel` | `null`. A `null` source means
  unreadable in the runner's privilege context — the EXPECTED outcome for
  PPL processes, NOT evidence of anything by itself. Defender-class
  escalations are closed by domain attribution, not by path resolution. Dead PIDs return
  `{ alive: false, note: "process exited" }` (expected for short-lived
  residuals — packet carries the recorded image path so `check_signature`
  / `hash_file` still work).
- Output: `{ chain: [ ...root-first... ], alive: true|false }`.

Deliberately NOT provided: DNS resolution, arbitrary file read, directory
listing, network connections listing (packet already contains it), any
web fetch, any process/service/registry manipulation.

## 2. Invocation (by Tier 1, verified against Claude Code docs 2026-08-26)

Packet JSON (schema `schemas/escalation-packet.schema.json`) is written to
`escalations/<ts>-packet.json` AND piped to stdin as the prompt body.
Attribution `source` values: `sni` (TLS ClientHello), `http-host`
(plaintext HTTP Host header — client-forgeable, weaker than SNI; normal
for port-80 CRL/OCSP fetches), `dns-pid`/`dns-ip` (live DNS ETW),
`dns-cache` (OS resolver cache, ambient), `none`.

```
& "<cfg.tier2.claude_exe>" `
  -p "Analyze the escalation packet provided on stdin per your system prompt." `
  --model sonnet `
  --output-format json `
  --system-prompt "<content of src/tier2/system-prompt.md>"   # replaces default; loaded by launcher
  --mcp-config src/tier2/mcp-config.json `
  --strict-mcp-config `                             # ignore user/project MCP configs
  --permission-mode dontAsk `
  --allowedTools "mcp__netwatch__check_signature,mcp__netwatch__hash_file,mcp__netwatch__check_reputation,mcp__netwatch__check_process_lineage" `
  --disallowedTools "Bash,Read,Write,Edit,NotebookEdit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite" `
  --max-turns 25 `
  < packet.json  > stdout.json 2> stderr.txt        # via Process redirects, see skeleton
```

Notes for the implementer (doc-verified behaviors):
- `--allowedTools` alone only PRE-APPROVES — it does not deny anything.
  The hard denial is the combination `--permission-mode dontAsk` (denies
  everything not allowed) + explicit `--disallowedTools` for every
  built-in (belt and suspenders; deny rules win over allow).
- System prompt: `--system-prompt <string>` (replace) and
  `--append-system-prompt-file <path>` (append) are doc-confirmed; a
  replace-from-file flag is not — so the launcher loads
  `system-prompt.md` into the `--system-prompt` string argument
  (ArgumentList entry, no shell quoting involved).
- `--output-format json` envelope carries `result` (the verdict JSON text)
  and `session_id` (needed by Tier 3). Exit code + envelope parsing rules
  in `skeletons/invoke-tier2.ps1`.
- Working directory: a dedicated runtime dir (state root), NOT the code
  repo — keeps session files and any accidental relative paths inside the
  sandbox area.
- The 180-s wall-clock cap and tree-kill live in the launcher, not in
  claude flags (`--max-turns` is a secondary bound on loop length only).

`src/tier2/mcp-config.json`:

```json
{
  "mcpServers": {
    "netwatch": {
      "type": "stdio",
      "command": "C:\\Program Files\\nodejs\\node.exe",
      "args": ["<code-root>\\src\\tier2\\mcp-server\\server.mjs"],
      "env": {
        "NETWATCH_STATE": "%LOCALAPPDATA%\\netwatch",
        "NETWATCH_PWSH": "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
      }
    }
  }
}
```

(API keys are injected by Tier 1 into the claude process environment so
the MCP child inherits them; they never appear in the config file, the
packet, or logs.)

## 3. Verdict contract (Tier 2 -> Tier 1)

Tier 2's final message must be EXACTLY one JSON object
(`schemas/verdict.schema.json`):

```json
{
  "verdict": "CLEAN" | "ALARM",
  "connections": [
    {
      "key": "<procname|domain-or-ip|port>",
      "assessment": "clean" | "suspicious",
      "reasons": ["..."],
      "evidence": ["check_signature: Valid, chain=...", "..."],
      "proposed_whitelist_entry": { ...whitelist entry object... }   // optional, clean only
    }
  ],
  "summary": "one paragraph"
}
```

Rules enforced by Tier 1's parser (2026-08-28: the schema itself is applied
via `Test-Json`; unknown EXTRA fields are tolerated by design — a paid
retry costs more than ignoring a harmless field — while type errors and
the rules below still reject the run):
- overall `verdict` must be ALARM if ANY connection is `suspicious`;
- non-JSON / schema-invalid output -> one retry, then Tier 3
  (`tier2_failed`);
- `proposed_whitelist_entry` objects go to `state/proposals.jsonl` only —
  never applied automatically (DECISIONS D1).

## 4. Tier-3 handoff

On ALARM / timeout / double failure, Tier 1 calls
`tier3/launch-tier3.ps1 -SessionId <id-or-empty> -AlarmFile <path>`:
urgent toast, then a visible pwsh 7 console window hosting a FRESH
interactive `claude` session whose prompt is fully constructed each time
(reason, keys, packet path, verdict path when present, and the Tier-2
session id as reference only — DECISIONS D7 as amended 2026-08-27; the
drifted headless context is never resumed automatically, though the human
may still run `claude --resume <id>` manually). Tier 3 is a
full-capability interactive session; the human is the permission system
from here on.
