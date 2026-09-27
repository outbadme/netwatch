# netwatch — tiered network-connection security monitor for Windows

Watches every TCP connection on a Windows 11 machine, explains almost all of
them automatically, and pulls in a human **only** for the genuinely
unexplained. Silence is the default outcome.

**Tier 1** — a PowerShell 7 scheduled task. Samples TCP connections every
30 s, attributes each one to a domain (whitelist + ETW DNS-Client events +
TLS SNI via tshark), enriches the leftovers with Team Cymru IP-to-ASN (free
DNS TXT, no account). Whitelisted traffic (and, if you opt in, attributed
traffic of pinned browsers) is just logged.

**Tier 2** — a headless Claude Code run (`sonnet`), invoked at most every
10 minutes and hard-capped at 3 minutes wall clock (the whole process tree is
killed on overrun). It receives only the small unclassified residual (max 20
connections) and returns a strict-JSON CLEAN/ALARM verdict. Its entire tool
surface is four read-only MCP helpers: `check_signature`, `hash_file`,
`check_reputation`, `check_process_lineage`. No shell, no file access, no web.
A CLEAN verdict only *suppresses* the connection for 24 h and files a
whitelist *proposal* — permanent whitelisting always goes through a human.

**Tier 3** — a fresh interactive `claude` session in a visible pwsh window
that opens only on ALARM, Tier-2 timeout, or double failure. The session id
is informational only (D7, amended). Human in the loop from there.

Design rationale and edge-case behavior: `ARCHITECTURE.md`, `DECISIONS.md`,
`TIER2-CONTRACT.md`, `FAILURE-MATRIX.md` (F1-F24).

## Requirements

- Windows 10/11, PowerShell 7.6+ (current stable): `winget install Microsoft.PowerShell`
- Node.js 24+ (LTS): `winget install OpenJS.NodeJS.LTS`
- Claude Code CLI 2.1.283+ with an active login: `npm install -g @anthropic-ai/claude-code@latest`
- Wireshark/tshark + Npcap (install below); optional AbuseIPDB / VirusTotal keys

## Install

```powershell
winget install --id WiresharkFoundation.Wireshark -e                      # tshark + Npcap
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864 # elevated: DNS attribution
Install-Module BurntToast -Scope CurrentUser -MinimumVersion 1.1.0 -Force # toasts
npm ci --ignore-scripts --prefix src\tier2\mcp-server                     # MCP server deps
pwsh -File install\init-deploy.ps1                                        # machine config + state + whitelist seed
pwsh -File install\register-task.ps1                                      # logon task
pwsh -File install\enable-sysmon.ps1 -SysmonExe <path>\Sysmon64.exe      # optional, elevated, Sysmon 15.0+
Start-ScheduledTask -TaskName netwatch-tier1
```

Npcap decision (one checkbox): leave "restrict to Administrators" ON and run
the task elevated, or UNCHECK it during install and the task runs fine
non-elevated. Either works; pick per your threat model.

Optional reputation keys: copy `.env.example` to `.env`, fill the values, then
`pwsh -File install\protect-keys.ps1 -EnvFile .env -DeleteSource`
(DPAPI-protected, current user only; without keys the pipeline still works —
reputation answers `no_key`).

Already running Sysmon? `enable-sysmon.ps1` refuses to touch it until you
choose: `-KeepExistingConfig` (your config must log TCP NetworkConnect) or
`-ReplaceExistingConfig` (the current config is saved under
`state\sysmon-backup-<time>\` first).

Check the machine at any time: `pwsh -File install\probe-environment.ps1
-Strict` exits 1 and lists every component that is missing or below its
minimum.

## Upgrade

```powershell
winget upgrade Microsoft.PowerShell; winget upgrade OpenJS.NodeJS.LTS
npm install -g @anthropic-ai/claude-code@latest
git pull; npm ci --ignore-scripts --prefix src\tier2\mcp-server
pwsh -File install\probe-environment.ps1 -Strict                        # all minimums met?
Stop-ScheduledTask -TaskName netwatch-tier1; Start-ScheduledTask -TaskName netwatch-tier1
```

Tasks registered before 2026-09-26 start `netwatch.ps1` directly: re-run
`install\register-task.ps1` once so the task uses `start-netwatch.ps1`. That
launcher checks the PowerShell version itself; if pwsh is too old the monitor
does not start, and says so in `%LOCALAPPDATA%\netwatch\logs\bootstrap.log`
and a toast instead of failing silently inside the hidden task.

## What it downloads / what leaves the machine

- Downloads: winget packages above + npm deps for the local MCP server. Tier 2
  runs on whatever your `claude` CLI login uses: with a Claude **subscription**
  there is no per-token bill — escalations draw from the same session quota as
  your interactive Claude windows; with an API key each escalation costs
  typically a few cents. Either way it is hard-bounded by the 3-min wall-clock
  cap, the 25-turn limit and the >= 10-min spacing between runs.
- Network egress at runtime: Team Cymru DNS TXT lookups for unclassified IPs;
  optional AbuseIPDB/VirusTotal lookups (Tier-2 only, free-tier quota-guarded:
  900/day, 400/day + 4/min). Your own public IP, RFC1918, CGNAT, loopback and
  link-local addresses are **never** sent to any lookup service — enforced in
  Tier 1 and again inside the reputation tool, not overridable by the model.
- DoH stays enabled; SNI capture covers the blind spot instead.

## Turn it off / uninstall

```powershell
Stop-ScheduledTask -TaskName netwatch-tier1; Unregister-ScheduledTask -TaskName netwatch-tier1 -Confirm:$false
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false              # optional: ETW back off
Remove-Item -Recurse $env:LOCALAPPDATA\netwatch                            # state, logs, keys
```

## Where the data lives

Code and state are strictly separated. Everything mutable is under
`%LOCALAPPDATA%\netwatch\`:

| Path | Content | Retention |
|---|---|---|
| `whitelist.json` | live whitelist (seeded from `config/whitelist.seed.json`) | until you edit it |
| `logs/` | op log + per-connection jsonl | 14 days |
| `escalations/` | every Tier-2 packet, raw output, verdict | 90 days |
| `alarms/` | ALARM records + open markers | 365 days |
| `state/` | suppression cache, proposals, own-IP, quota ledger, DPAPI keys | working state |

**Expect the first days to be noisy — that is the design, not a bug.** The
shipped whitelist is EMPTY and no browser gets blanket credit (DECISIONS
D12): nothing is trusted until it was checked on THIS machine. Until the
whitelist learns the regular cast of
your traffic (your browsers, updaters, agents, VPNs) Tier 2 will produce a
burst of one-time CLEAN verdicts and proposals. Week 1 routine: review
`state\proposals.jsonl` (entries marked `double_clean` first) and promote the
good ones into `whitelist.json` by hand — suppression alone expires every
24 h. After that, silence becomes the normal state.

## Honest limitations

- Connections are polled every 30 s. A connection that opens and closes
  between two polls is invisible to polling; with Sysmon installed
  (`install/enable-sysmon.ps1`, config `config/sysmon-netwatch.xml` - only
  NetworkConnect is logged) netwatch also drains Sysmon event 3 each tick
  and sees those. Without Sysmon every packet says `sysmon: unavailable`.
- Whitelist entries match on the process NAME. For well-known names Tier 1
  pins the identity (`src/tier1/modules/identity.psm1`): `svchost`,
  `explorer`, `taskhostw`, `runtimebroker`, `backgroundtaskhost` must run
  from their System32/Windows path; `msedge` (any channel) and the
  Evergreen `msedgewebview2` must run from their Program Files / per-user
  Edge roots AND carry a valid Microsoft Corporation signature
  (fixed-version WebView2 runtimes inside apps need a `process_images` entry);
  a process named `dosvc` is always an impostor (DoSvc runs inside
  svchost). Otherwise the connection gets no whitelist and no browser
  credit. Add or override pins (paths, optional Authenticode signers) in
  `whitelist.json` under `process_images`; browser names without a pin are
  logged as a WARN at startup. When the image path is unreadable
  (non-elevated task, SYSTEM processes) only entries that also name a
  destination still match by name - no browser credit and no any-peer
  entry (e.g. Delivery Optimization on 7680).
- SNI is captured only on ports 443/8443 (`sni.capture_ports`) and plaintext
  HTTP Host headers only on `sni.http_ports` (default 80 — attributes
  CRL/OCSP-class traffic as source `http-host`; the header is written by the
  client, so it is weaker evidence than SNI). Both are config-extendable;
  other ports ride on DNS attribution or escalate unattributed.
- If both attribution sources go down, a flood guard stops Tier-2 spam and
  raises one urgent toast instead.
- Deleting an alarm's `*-open.marker` file is how a human closes an
  investigation and re-arms escalation for those connections.

## Tests

`pwsh -NoProfile -File tests\run-tests.ps1` — self-contained harness, no
Pester, no admin, no live Claude calls (Tier 2 is stubbed).

CI (`.github/workflows/windows-tests.yml`) runs the same suite on a Windows
runner in batches, not per push: when a PR is opened / reopened / marked
ready, when the `run-windows-ci` label is added, or manually from Actions.

## License

MIT (see `LICENSE`).
