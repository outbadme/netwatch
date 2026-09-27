# Design Decisions (resolutions of the design brief's open items + additional)

Format: decision, rationale, rejected alternatives. IDs referenced from
ARCHITECTURE.md.

---

## D1 — Whitelist schema and update/confirmation mechanism

**Schema**: JSON file validated by `schemas/whitelist.schema.json`.
The repo carries the SEED (`config/whitelist.seed.json`); the live file is
`paths.whitelist` (default `%LOCALAPPDATA%\netwatch\whitelist.json`),
seeded from the repo file at deploy. Entry = match block (domain exact list,
domain suffix list, CIDR list, optional process names, optional ports) +
provenance (added_by: seed|human|tier3, added_at, evidence text). Domain
match is primary (survives CDN/edge IP churn — the GOAL's core lesson);
CIDR entries exist only for traffic that has no domain (Telegram DC range,
Tailscale-internal RDP).

**Update mechanism — Tier 2 does NOT get permanent whitelist power.**

- On CLEAN, Tier 2 returns `proposed_whitelist_entry` objects in its
  verdict. Tier 1 appends them to `state/proposals.jsonl` and adds the
  connection keys to the **suppression cache** with TTL 24 h.
- Suppression = temporary silence only: the same key will not re-trigger
  Tier 2 until the TTL expires; after expiry the key is re-examined from
  scratch. A second independent CLEAN marks the proposal `double-clean` in
  `proposals.jsonl`.
- Permanent whitelist entries are added only by a human: either directly
  editing `whitelist.json`, or inside a Tier-3 session (human-supervised)
  — Tier 3 may apply a proposal, which sets `added_by: tier3` plus the
  evidence trail.

**Why**: Tier 2 is the component that ingests untrusted data (domains,
process command lines) and is therefore the prompt-injection surface. If a
CLEAN verdict could permanently whitelist, one successful injection would
create a permanent blind spot. With this design the worst case is a 24-h
suppression of a single key, every CLEAN is still logged and toasted, and
the proposal queue is human-reviewed. Cost: legitimate new domains get
re-checked once per 24 h until a human confirms — acceptable, Tier-2 runs
are cheap and silent.

**Rejected**: auto-whitelist on single CLEAN (injection risk above);
auto-whitelist after N consecutive CLEANs with no human (same risk, just
slower); no suppression at all (would re-invoke Tier 2 every 10 min for
the same benign residual — noise and quota burn).

## D2 — Sampling interval and Tier-2 debounce

- **Sample interval: 30 s** (config `sample_interval_sec`, valid 20–60).
  Midpoint of the GOAL's range; TCP connections that matter for attribution
  live well beyond 30 s or are caught by the age rule below.
- **Debounce to escalatable**: residual key must be seen in >= 2 samples
  OR have first-seen age >= 60 s. Rule 2 exists for short-lived
  connections (beacon-style: connect, exchange, close inside one sample
  window) — they escalate ~60 s after first sighting rather than never.
- **Tier-2 spacing: >= 10 min between launches** (config
  `tier2.min_interval_min`), EXCEPT immediate triggers: (a) unclassified
  inbound connection, (b) residual process whose image file is gone from
  disk. Batch cap: EFFECTIVE cap is `min(tier2.batch_cap (default 20),
  floor(tier2.wall_clock_cap_sec / tier2.sec_per_key_budget))` keys per
  packet (2026-08-27 clamp, `Get-EffectiveBatchCap`; live config budget 45
  -> cap 4); overflow flagged in the packet.
- Whitelist-matched CDN churn never reaches the residual queue at all
  (domain matching), so it cannot invoke Tier 2 — the specific failure
  mode the GOAL calls out.
- Cost note (2026-08-28): Tier 2 runs on the claude.ai subscription
  (OAuth token); envelope `cost_usd` is an API-equivalent estimate, not a
  real charge. What spacing and the batch cap actually protect is the
  shared session quota — TIER2-CONTRACT §0.

## D3 — 3-minute cap implementation: `System.Diagnostics.Process` + `Kill($true)`

**Decision**: launch claude via `[System.Diagnostics.ProcessStartInfo]`
(RedirectStandardInput/Output/Error), write the packet to stdin, then
`$proc.WaitForExit(180000)`; on timeout `$proc.Kill($true)`.

**Why**:
- `.Kill($true)` ("entire process tree") is documented .NET (Core 3.0+;
  pwsh 7 runs .NET 8+) and terminates descendants — critical because
  `claude.exe` spawns `node.exe` children (and the MCP server as a
  grandchild); killing only the root would orphan them.
- `Start-Job`/`Wait-Job -Timeout` + `Remove-Job -Force` was the GOAL's
  alternative: rejected because Remove-Job kills the job's pwsh host
  process, with no documented guarantee about the grandchild tree, and
  adds a useless intermediate pwsh process.
- `Start-Process -PassThru` cannot redirect stdin; passing a large packet
  as an argv string hits quoting hazards (explicitly banned by GOAL for
  PowerShell code, same class of risk for JSON) and command-line length
  limits. Stdin piping is the documented headless-mode input path
  (10 MB cap — orders of magnitude above packet size).

Concrete code: `src/tier1/invoke-tier2.ps1`.

## D4 — Toast mechanism: BurntToast module (pinned >= 1.1.0)

**Decision**: `BurntToast` from PSGallery, used ONLY via
`New-BurntToastNotification` (plus `-Urgent`-style options for ALARM),
wrapped in `tier1/modules/toast.psm1` with a fallback (log ERROR +
`msg.exe`-style console fallback is NOT used; failure to toast never
blocks the pipeline — the alarm surface is the Tier-3 window, not the
toast).

**Why**: raw WinRT interop (`Windows.UI.Notifications`) is not loadable in
pwsh 7 with the classic `[Windows.UI...,ContentType=WindowsRuntime]`
syntax (works only in PS 5.1, which is banned on this machine); doing it
"natively" means bundling the same `Microsoft.Windows.SDK.NET` projection
DLLs that BurntToast already ships. Verified 2026-08-26: basic toast
generation works on pwsh 7.x with current BurntToast (1.1.0); the
known-unreliable parts (toast history/removal, Update-BTNotification) are
not used by this design. Sources: github.com/Windos/BurntToast issues
#101/#120/#136; 4sysops BurntToast review (pwsh 7.3 working state);
PSGallery BurntToast 1.1.0.

One-time implementer step: `Install-Module BurntToast -Scope CurrentUser`.

## D5 — Log/audit retention

| Location (state root `%LOCALAPPDATA%\netwatch\`) | Content | Retention |
|---|---|---|
| `logs/conn-YYYYMMDD.jsonl` | every classified connection (one line per key per lifetime) | 14 days |
| `logs/netwatch-YYYYMMDD.log` | Tier-1 operational log | 14 days |
| `escalations/*` | packet + verdict + raw stdout/stderr per Tier-2 run | 90 days |
| `alarms/*` | ALARM packets + resolution notes | 365 days |
| `state/proposals.jsonl` | whitelist proposals | until human accept/reject |
| Claude session files (`~/.claude/projects/...`) | Tier-2/3 transcripts | Claude Code's own retention; escalations/ keeps the authoritative copy |

Enforced by the daily housekeeping tick (delete files older than the
window; failures logged, never fatal). Rationale: conn logs are bulky and
only needed for short-horizon correlation; escalations are the audit trail
of every automated judgment (90 d covers a quarterly review); alarms are
rare and precious.

## D6 — MCP server implementation: Node + official `@modelcontextprotocol/sdk`

Stdio MCP server (`src/tier2/mcp-server/server.mjs`) run by the official
`C:\Program Files\nodejs\node.exe`. Each tool shells out to a fixed
`.ps1` file via `pwsh -File` (never inline `-Command` — GOAL rule) and
returns the script's JSON stdout. Why Node over a PowerShell-native MCP
server: official SDK, trivial stdio framing, node is already a trusted
binary on this machine; the actual system access stays in reviewable
single-purpose .ps1 files. Python rejected: adds a runtime dependency the
pipeline otherwise doesn't need.

## D7 — Tier-3 continuation mechanism: `--resume <session_id>`, not bare `-c`

Verified against current Claude Code docs (2026-08-26): sessions created
by headless `claude -p` are excluded from `claude --continue`'s picker;
the documented way to reopen them interactively is
`claude --resume <session_id>`, with the id taken from the `session_id`
field of Tier 2's `--output-format json` envelope (cross-directory resume
supported since CLI v2.1.223). So `launch-tier3.ps1` receives the session
id from Tier 1 and runs `claude --resume <id>` in a visible window —
which fulfills the GOAL's "same session, continued visibly" intent
(`claude -c` in the GOAL text names the intent, not the working flag for
headless-created sessions). Fallback when no session id exists (Tier 2
died pre-session): fresh visible `claude` with the alarm packet path in
the prompt.

**Amended 2026-08-27 (operator decision):** Tier 3 no longer resumes the
Tier-2 session at all. Every Tier-3 window is a fresh interactive session
with a fully constructed prompt (reason, keys, packet path, verdict path,
tier2 session id as reference only) so the drifted headless context never
leaks into the human review; the window is a normal pwsh 7 console hosting
the agent. `--resume <id>` remains available to the human manually — the
id is printed in the prompt.

## D8 — Tier-1 process model: scheduled task at logon, user session, mutex

Runs as the interactive user (toasts and visible Tier-3 windows require
the interactive session), highest available privileges (ETW channel read +
packet capture). Single instance via named mutex `Global\netwatch-tier1`.
No Windows service: services can't toast or open windows in session >= 1,
and a service would be a new always-on privileged daemon the GOAL's
success criteria discourage.

## D9 — Timeout salvage: a finished verdict is not discarded (2026-08-28)

Operator-approved via the egress-switching task prompt. Live evidence
(run 20260828-103245-317): Tier-2 finished the whole 6-key analysis at
182 s against the 180 s cap; the salvaged stdout held a complete valid
CLEAN verdict — and it was discarded, raising Tier-3 on all six keys.

Policy: on wall-clock timeout the launcher parses the salvaged stdout.
A COMPLETE verdict passing the full shape validation is accepted exactly
like a normal run (exit 0) — F1's intent ("timeout means unfinished
analysis, a human decides") is not violated because the analysis IS
finished. A PARTIALLY valid verdict applies per validated connection
only (exit 5): covered-clean keys get the normal CLEAN handling,
covered-suspicious and uncovered keys go to Tier-3. Nothing that fails
validation is ever treated as clean; an unparsable salvage keeps the
original F1 path (exit 2).

## D10 — Tier-3 window lifecycle: fixed placement + idle auto-close (2026-08-28)

Operator request: investigation windows must not hang unattended.

- Placement: the window opens at the TOP-RIGHT corner of the rightmost
  screen (operator's right monitor) — visible, never in the way.
  Implemented as SELF-positioning: the payload pwsh moves its own console
  window (`tier3win.psm1`, GetConsoleWindow + MoveWindow), because under
  the default Windows Terminal host a launched process has no
  MainWindowHandle and the window cannot be found from outside. The
  launcher therefore hosts the payload in `conhost.exe` explicitly.
  Placement is cosmetic and fail-soft everywhere.
- Idle auto-close: a hidden watchdog (`tier3/tier3-watchdog.ps1`, spawned
  by the launcher) closes the window after `tier3.idle_close_min` (default
  5, 0 disables) minutes of GLOBAL input idle (GetLastInputInfo).
  Rationale for global idle over window focus (operator's pick): simple,
  robust, and closes windows only when the operator has actually walked
  away. A broken idle sensor fails OPEN (never closes).
- On ANY close (idle or operator/agent ended) the watchdog writes a report
  to `tier3.report_dir` (default `<Desktop>\netwatch`, created on demand):
  UTC open/close, reason, keys, packet path, tier-2 session id, verdict
  presence. The watchdog is a plain pwsh child, NOT a claude session — the
  PreToolUse jail hooks do not apply to it, which is exactly why IT (not
  the agent) can write to the Desktop, outside the jail roots.

## D11 — do-log attribution: Connected Cache IP rotation defeated per-IP whitelisting (2026-08-29)

Problem: DoSvc fetches Windows Update content over HTTP:80 from Microsoft
Connected Cache (MCC) nodes whose IPs are assigned dynamically by the DO
GEO service and ROTATE (193.57.46.213 on 08-28, 193.57.46.231 on 08-29).
No SNI (plaintext), often no http.host in the capture window, no PTR —
every rotation produced a `source: none` escalation of a benign class;
per-IP whitelist entries were whack-a-mole, a /24 whitelist was rejected.

Decision: a new attribution source `do-log`, consulted LAST in the chain
(only when every other source is `none`) and ONLY for svchost/dosvc on
port 80. If the connection's remote IP is recorded as a `CacheHost` in
the machine's own Delivery Optimization records
(`Get-DeliveryOptimizationStatus` — unelevated; `Get-DeliveryOptimizationLog`
— admin, conservative parse), the IP is a Microsoft Connected Cache node
and the connection is attributed to the CONTENT origin host from the
record's SourceURL (e.g. `*.dl.delivery.mp.microsoft.com`) — never to the
cache node itself. Fail-open to `none` on any evidence-source failure;
results cached 10 min. The endpoint-vs-content distinction is taught to
Tier 2 in the system prompt so the weaker endpoint identity is graded
correctly.

Rejected: a `193.57.46.0/24` whitelist entry (operator, 2026-08-29) —
whitelisting an entire third-party hosting block for svchost:80, however
narrow the process pin, permanently over-permits against a rotating
assignment; the journal-based attribution is evidence, the whitelist
would be faith.

## D12 — Post-compromise reset: no inherited trust (2026-09-27)

Context: the machine netwatch was built and tuned on was running a RAT
(created local users and privileges; used npm packages, WinSxS
substitution and msedgewebview2). Every trust decision made from that
machine's observations is therefore unverified.

Decisions:
- Seed whitelist shipped EMPTY. The former entries (Microsoft suffixes incl.
  customer-hostable CDNs, observed CIDRs, any-peer svchost:7680, inbound RDP
  from a tailnet peer, Telegram by name, node to LLM APIs, Octo Browser,
  bank CA endpoints, CRL hosts, caBLE) were derived there; they survive only
  as SYNTHETIC test data in `tests/fixtures/whitelist.fixture.json`.
- `browser_attributed_ok` defaults to empty: a listed name trusts any
  domain it reaches. `msedgewebview2` must never be listed - any program
  (the RAT included) can embed the genuine, Microsoft-signed runtime.
- Tier-2 prompt: the owner profile ("pentester workstation", "cheap VPS /
  reputation are weak signals because the owner's C2 looks like that",
  "exploit tooling is the normal toolset") is removed - it described the
  RAT's own traffic profile as normal. Reputation, hosting ASNs and missing
  attribution are real signals; `mismatch` is always suspicious; unsigned
  binaries are always hashed; runtimes (WebView2, node, script hosts) are
  judged by their host process; `do-log` is a local, forgeable claim.
- Tier 3 runs with `--permission-mode default` (was `auto`, 2026-08-29): an
  automatically opened agent, prompted from attacker-shapeable data, must
  not execute commands without the human approving each one. Connection
  keys are no longer inlined in its prompt.
- `install/verify-packages.ps1` fails (exit 1) unless size, hash AND a
  Valid Authenticode signature all pass.

Known limit, not fixed here: identity pins check the executable's path and
signer, not the DLLs it loads - side-loading (WinSxS or a planted DLL next
to a signed binary) and injection into a legitimate process are invisible
to Tier 1.

