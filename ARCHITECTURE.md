# Tiered Network-Connection Security Monitor — Build Architecture

Status: design complete, ready for implementer.
Scope: per the original design brief (2026-08-26) and `README.md` (scope rules).
Companion documents: `DECISIONS.md` (rationale for every open item),
`TIER2-CONTRACT.md` (Tier-2 tool surface), `FAILURE-MATRIX.md` (edge cases),
`schemas/` (JSON Schemas), `src/` (implementation).

All PowerShell in this system runs under pwsh 7
(`C:\Program Files\PowerShell\7\pwsh.exe`) — never `powershell.exe` 5.1
(known machine bug: `Microsoft.PowerShell.Security` silently fails to load).
Cross-shell invocation is always `pwsh -File <script.ps1> <args>` — never
inline `-Command` strings (escaping mangling, per GOAL).

---

## 1. Component overview

```
+---------------------------------------------------------------------------+
| Tier 1: netwatch.ps1 (pwsh 7, always running, single instance via mutex)  |
|                                                                           |
|  [sampler] ---- Get-NetTCPConnection every 30 s ----------------+         |
|  [dns-etw] ---- Get-WinEvent bookmark reader, events 3006/3008 -+--> join |
|  [sni-cap] ---- tshark child proc, TLS ClientHello SNI ---------+    |    |
|                                                                      v    |
|  [classify] domain/CIDR whitelist match  -- matched --> conn log (jsonl)  |
|       | residual (unclassified)                                           |
|       v                                                                   |
|  [enrich]  Team Cymru ASN (DNS TXT, own-IP/private excluded)              |
|       v                                                                   |
|  [escalate] debounce -> escalation packet -> invoke Tier 2 (3-min cap)    |
+-----------------------------|---------------------------------------------+
                              v
+---------------------------------------------------------------------------+
| Tier 2: claude (headless, model sonnet), MCP-only tool surface            |
|   tools: check_signature, hash_file, check_reputation,                    |
|          check_process_lineage   (read-only; see TIER2-CONTRACT.md)       |
|   output: strict JSON verdict  CLEAN | ALARM                              |
+------------|----------------------------------|---------------------------+
        CLEAN|                                  |ALARM / timeout / crash
             v                                  v
      toast notification              +---------------------------+
      + suppression cache             | Tier 3: fresh interactive |
      + whitelist proposal            | claude in a pwsh window   |
        (pending human confirm)       | (human; D7 as amended)    |
                                      +---------------------------+
```

No separate supervisor: Tier 1's loop is the orchestrator (per GOAL).

## 2. Directory layout

Two roots, deliberately separated:

**Code root** (implementer's choice, e.g. `C:\tools\netwatch\`; everything
relative below):

```
src/
  tier1/
    netwatch.ps1              # entry point + main loop + orchestration
    modules/
      sampling.psm1           # TCP connection snapshots
      dnsetw.psm1             # ETW DNS-Client event reader (bookmarked)
      snicapture.psm1         # tshark child-process manager + SNI cache
      classify.psm1           # whitelist matching, residual queue, debounce
      enrich.psm1             # Cymru ASN lookups, own-IP detection/exclusion
      escalate.psm1           # packet builder, Tier-2 invocation, verdict handling
      state.psm1              # state files, suppression cache, log rotation
      toast.psm1              # BurntToast wrapper
  tier2/
    mcp-server/
      server.mjs              # Node stdio MCP server (official SDK)
      package.json
    tools/
      check-signature.ps1
      hash-file.ps1
      check-reputation.ps1
      check-process-lineage.ps1
    system-prompt.md          # fixed Tier-2 prompt (see prompts/)
    mcp-config.json           # per-invocation MCP config for claude CLI
  tier3/
    launch-tier3.ps1          # visible continuation window
config/
  netwatch.config.json        # tunables (see schemas/config.schema.json)
  whitelist.json              # live whitelist (seeded from whitelist.seed.json)
install/
  register-task.ps1           # scheduled-task registration (logon, user context)
  enable-etw.ps1              # wevtutil channel enable (implementer runs once)
```

**State root**: `%LOCALAPPDATA%\netwatch\` (survives code updates, never in
the repo):

```
state/
  ownip.json                  # detected public IP + static recorded value
  suppression.json            # CLEAN-verdict suppression cache (TTL entries)
  proposals.jsonl             # Tier-2 whitelist proposals awaiting human confirm
  etw-bookmark.xml            # last-read ETW event position
  repquota.json               # AbuseIPDB/VT daily+minute quota ledger
logs/
  conn-YYYYMMDD.jsonl         # classified connection log (14 d)
  netwatch-YYYYMMDD.log       # Tier-1 operational log (14 d)
escalations/
  <ts>-packet.json            # what was sent to Tier 2 (90 d)
  <ts>-verdict.json           # what Tier 2 answered, incl. session id (90 d)
  <ts>-stdout.json / -stderr.txt
alarms/
  <ts>-alarm.json             # ALARM packets + resolution notes (365 d)
```

## 3. Tier 1 — collector + orchestrator

Single pwsh 7 process. Started by a Scheduled Task at user logon (runs in the
user's interactive session — required for toast notifications and for
launching a visible Tier-3 window; admin rights required for ETW channel read
and tshark capture — task runs with highest privileges available to the
user). Single-instance guard: named mutex `Global\netwatch-tier1` acquired at
startup; if held, exit immediately.

### 3.1 Main loop (every `sample_interval_sec`, default 30)

1. **Sample** `Get-NetTCPConnection` (states: Established, SynSent, plus
   Listen for inventory) with `OwningProcess`; resolve PID -> process name +
   image path once per PID per lifetime (CIM `Win32_Process`, cached).
2. **Drain DNS-ETW**: `Get-WinEvent` on
   `Microsoft-Windows-DNS-Client/Operational` from the saved bookmark;
   events 3006 (query) / 3008 (query completed) yield
   `(pid, domain, resolved IPs)`. Feed two caches:
   `ip -> [domains]` and `(pid, ip) -> domain` (preferred, more precise).
   Cache TTL 2 h, bookmark persisted every drain.
3. **Drain capture**: read pending lines from the tshark child's stdout
   (fields: `ip.dst`/`ipv6.dst`, `tcp.dstport`, SNI, `http.host` — the last
   field added 2026-08-28: plaintext HTTP on `sni.http_ports`, default 80,
   attributes CRL/OCSP-class traffic via the Host header). Feed cache
   `ip:port -> domain(+source)`. TTL 2 h. tshark supervision: see
   FAILURE-MATRIX §Npcap.
4. **Attribute** each new connection `(pid, procname, raddr, rport)`:
   domain := capture cache `(raddr:rport)` (source `sni` or `http-host`) ->
   else DNS cache `(pid, raddr)` -> else DNS cache `(raddr)` -> else OS
   resolver cache `(raddr)` (`Get-DnsClientCache`, added 2026-08-27: works
   even when the capture is blind behind the VPN data-channel offload and
   ETW missed the lookup) -> else, for svchost/dosvc on port 80 only, the
   Delivery Optimization records (`do-log`, added 2026-08-29, DECISIONS
   D11: a CacheHost match means the endpoint is a Microsoft Connected
   Cache node; those rotate, so the domain shown is the CONTENT origin
   from the DO SourceURL) -> else none. Record attribution source
   (`sni` / `http-host` / `dns-pid` / `dns-ip` / `dns-cache` / `do-log` /
   `none`) — Tier 2/3 must know how solid the attribution is (`http-host`
   is client-forgeable, weaker than `sni`).
5. **Classify** against `whitelist.json` (domain-suffix match first, then
   CIDR entries, optional process/port/direction constraints — see
   `schemas/whitelist.schema.json`). Matched -> one line in
   `conn-*.jsonl`, nothing else. Browser policy (config
   `classify.browser_attributed_ok`, default msedge/msedgewebview2): any
   browser connection WITH domain attribution is treated as clean-logged
   (user-driven browsing churn — an unwhitelistable domain set), while
   browser connections WITHOUT attribution (raw-IP, no SNI, no DNS) stay
   escalatable. Own-machine noise (loopback, link-local, both ends local)
   is logged at trace level only.

   **Egress-proxy boundary (2026-08-28, design limit — not a defect):**
   when traffic leaves through a remote rotating proxy (Octo Browser), the
   machine establishes TLS to the PROXY endpoint; the true destination
   lives INSIDE that tunnel and is not observable on the wire. netwatch
   can attribute only the proxy hop itself — empty attribution on a proxy
   flow means "inside the tunnel", never stealth. Consequence: the proxy
   process's remote addresses rotate constantly, so `/32` whitelist
   entries are meaningless for it; the correct form is process + provider
   domain suffix (the `octo-browser` seed entry), with the
   `browser_attributed_ok` mechanism covering the rest (attributed =
   clean-logged, unattributed = escalatable).
6. **Residual handling**: unmatched connections enter the residual queue
   keyed by `(procname, domain-or-raddr, rport)`. Debounce (see
   DECISIONS D2): a key becomes *escalatable* when it has been seen in >= 2
   samples OR is >= 60 s old (catches short-lived beacons that appear in a
   single sample and vanish). Keys in the suppression cache
   (prior CLEAN, TTL not expired) or already escalated-and-pending are
   skipped.
7. **Enrich** escalatable keys: Team Cymru ASN via DNS TXT
   (`<reversed-ip>.origin.asn.cymru.com`, then `AS<n>.asn.cymru.com` for
   AS name). Hard exclusion before any external lookup (Cymru here;
   AbuseIPDB/VT are Tier-2-only): own public IP (dynamic + recorded static
   `203.0.113.10`), RFC1918, 100.64.0.0/10 (Tailscale CGNAT), loopback,
   link-local, multicast/reserved.
8. **Escalation decision**: if the escalatable set is non-empty AND
   (>= `tier2.min_interval_min` (default 10) since last Tier-2 launch OR an
   immediate trigger fired), build the escalation packet
   (`schemas/escalation-packet.schema.json`) and invoke Tier 2.
   Immediate triggers (bypass the 10-min spacing): an unclassified
   **inbound** connection (remote endpoint initiated, non-whitelisted), or
   a residual process whose image file no longer exists on disk.
9. **Housekeeping** (first tick after local midnight): log rotation +
   retention (DECISIONS D5), own-IP re-detect (also hourly), quota ledger
   reset.

### 3.2 Own-IP handling

At startup and hourly: `Resolve-DnsName myip.opendns.com -Server
resolver1.opendns.com` (plus `-Type AAAA` variant). Result stored in
`state/ownip.json` next to the permanently recorded `203.0.113.10`.
The exclusion set = {current detected, last-known, recorded static}. If
detection fails, the exclusion set keeps last-known + static (fail closed:
never "no exclusions"). These IPs are never sent to Cymru/AbuseIPDB/VT —
enforced twice: in `enrich.psm1` and again inside the `check_reputation`
MCP tool (defense in depth, since Tier 2 receives untrusted data).

### 3.3 Tier-2 invocation and the 3-minute cap

`escalate.psm1` launches `claude` headless via `System.Diagnostics.Process`
(NOT `Start-Job` — see DECISIONS D3): packet JSON written to
`escalations/<ts>-packet.json` and also piped to stdin as the prompt body;
stdout/stderr redirected to files. Then:

- `$proc.WaitForExit(180000)` — hard wall-clock cap 180 s.
- On timeout: `$proc.Kill($true)` — .NET "kill entire process tree", which
  takes down claude.exe *and* its node.exe descendants — then try to
  salvage the captured stdout (DECISIONS D9, 2026-08-28): a COMPLETE
  schema-valid verdict is accepted like a normal run; a partially valid one
  applies per validated connection and ONLY the uncovered/suspicious keys
  reach Tier 3 (reason `tier2_timeout`/`alarm`); nothing salvageable ->
  Tier 3 immediately with reason `tier2_timeout` on the whole batch.
- On exit within cap: parse stdout JSON (verdict schema). `ALARM` ->
  Tier 3 immediately. `CLEAN` -> toast + suppression-cache entries (TTL
  24 h) + append whitelist proposals to `state/proposals.jsonl`.
- Unparseable output / nonzero exit: one retry; second failure -> Tier 3
  with reason `tier2_failed` (fail loud, never fail silent).

Exact command line, tool restriction flags, and MCP config: see
`TIER2-CONTRACT.md`. Concrete cap code: `src/tier1/invoke-tier2.ps1`.

## 4. Tier 2 — headless analyst (summary; full contract in TIER2-CONTRACT.md)

- `claude` CLI, model sonnet, headless print mode, JSON output.
- Tool surface = exactly four read-only MCP tools served by a local Node
  stdio MCP server; every built-in tool (Bash, Read, Write, Edit, Web*) is
  denied. Containment is the absence of capability, not a permission filter.
- Fixed prompt (`prompts/tier2-system-prompt.md`): machine context baked in
  (pentester's workstation, weak-signal reputation policy, pwsh-7 rule),
  data-not-instructions clause, fixed check sequence, strict JSON verdict.
- Reputation lookups (AbuseIPDB/VT) exist ONLY here, quota-guarded, and
  refuse own/private/CGNAT IPs regardless of what the model asks.
- On CLEAN Tier 2 does NOT get to permanently whitelist anything — it emits
  a *proposal*; permanence requires human/Tier-3 confirmation
  (DECISIONS D1).

## 5. Tier 3 — visible continuation

`tier3/launch-tier3.ps1`, called by Tier 1 on ALARM/timeout/failure:

1. Fire an urgent toast ("NETWATCH ALARM — investigation window opening").
2. Launch a visible pwsh 7 console window (conhost-hosted, parked at the
   rightmost screen's top-right corner — DECISIONS D10) hosting a FRESH
   interactive `claude` session (DECISIONS D7 as amended 2026-08-27). The
   prompt is fully constructed per alarm: reason, affected keys, packet
   path, verdict path when present, and the Tier-2 session id as reference
   only — the headless session's drifted context is never resumed
   automatically. A hidden watchdog auto-closes the window after
   `tier3.idle_close_min` (default 5) minutes of operator input idle and
   reports every close to `<Desktop>\netwatch\` (D10).
3. Write `alarms/<ts>-alarm.json`; Tier 1 keeps running (monitoring does
   not stop during investigation) but suspends further Tier-2 launches for
   the same keys while the open-marker exists. Deleting the marker is the
   operator's resolution: the keys are evicted from the residual queue and
   suppressed for the standard TTL (cooldown), not instantly re-escalated.

Tier 3 is a normal interactive Claude Code session — full tools, human in
the loop, investigative standard per GOAL (hash comparison against
upstream, PE imports, parent-process tracing; never trust name/signature
alone).

## 6. Data contracts (schemas/)

| Schema | Producer -> Consumer | File |
|---|---|---|
| `whitelist.schema.json` | human/seed -> Tier 1 | repo seed `config/whitelist.seed.json`; live `paths.whitelist` |
| `config.schema.json` | human -> Tier 1 | `config/netwatch.config.json` |
| `escalation-packet.schema.json` | Tier 1 -> Tier 2 (stdin + file) | `escalations/*-packet.json` |
| `verdict.schema.json` | Tier 2 -> Tier 1 (stdout) | `escalations/*-verdict.json` |

Seed whitelist content (from the GOAL baseline): `config/whitelist.seed.json`.

## 7. Security posture summary

- **Prompt-injection containment**: Tier 2 sees untrusted data (process
  names, domains, command lines) but its worst case is bounded: no
  destructive tools exist; a poisoned CLEAN buys at most a 24-h suppression
  of one key and a *pending* proposal that a human reviews; a poisoned
  ALARM just summons the human (fail-safe direction).
- **Secrets**: AbuseIPDB/VT keys live in env vars of the MCP server process
  (set by Tier 1 from a DPAPI-protected file `state/apikeys.dat`), never in
  prompts, never in logs.
- **Privacy**: DoH stays on; own public IP never leaves the machine toward
  reputation services; `C:\Users\YOURNAME\Downloads` is a hard-denied path in
  every tool's input validation.
- **No new always-on daemons** beyond Tier 1 itself + the Npcap driver
  (accepted exception per GOAL); the MCP server and tshark are children of
  Tier 1/Tier 2 lifecycles.
