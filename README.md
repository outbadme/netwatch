# netwatch — tiered network-connection security monitor for Windows

Watches every TCP connection on a Windows 11 machine, explains almost all of
them automatically, and pulls in a human **only** for the genuinely
unexplained. Silence is the default outcome.

**Tier 1** — a PowerShell 7 scheduled task. Samples TCP connections every
30 s, attributes each one to a domain (whitelist + ETW DNS-Client events +
TLS SNI via tshark), enriches the leftovers with Team Cymru IP-to-ASN (free
DNS TXT, no account). Whitelisted and browser-attributed traffic is just
logged.

**Tier 2** — a headless Claude Code run (`sonnet`), invoked at most every
10 minutes and hard-capped at 3 minutes wall clock (the whole process tree is
killed on overrun). It receives only the small unclassified residual (max 20
connections) and returns a strict-JSON CLEAN/ALARM verdict. Its entire tool
surface is four read-only MCP helpers: `check_signature`, `hash_file`,
`check_reputation`, `check_process_lineage`. No shell, no file access, no web.
A CLEAN verdict only *suppresses* the connection for 24 h and files a
whitelist *proposal* — permanent whitelisting always goes through a human.

**Tier 3** — a visible `claude --resume <session_id>` window that opens only
on ALARM, Tier-2 timeout, or double failure. Human in the loop from there.

Design rationale and edge-case behavior: `ARCHITECTURE.md`, `DECISIONS.md`,
`TIER2-CONTRACT.md`, `FAILURE-MATRIX.md` (F1-F24).

## Requirements

- Windows 10/11, PowerShell 7: `winget install Microsoft.PowerShell`
- Node.js 20+: `winget install OpenJS.NodeJS.LTS`
- Claude Code CLI 2.1.223+ with an active login: `npm install -g @anthropic-ai/claude-code`
- Wireshark/tshark + Npcap (install below); optional AbuseIPDB / VirusTotal keys

## Install

```powershell
winget install --id WiresharkFoundation.Wireshark -e                      # tshark + Npcap
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864 # elevated: DNS attribution
Install-Module BurntToast -Scope CurrentUser -MinimumVersion 1.1.0 -Force # toasts
npm ci --prefix src\tier2\mcp-server                                      # MCP server deps
pwsh -File install\init-deploy.ps1                                        # machine config + state + whitelist seed
pwsh -File install\register-task.ps1                                      # logon task
Start-ScheduledTask -TaskName netwatch-tier1
```

Npcap decision (one checkbox): leave "restrict to Administrators" ON and run
the task elevated, or UNCHECK it during install and the task runs fine
non-elevated. Either works; pick per your threat model.

Optional reputation keys: copy `.env.example` to `.env`, fill the values, then
`pwsh -File install\protect-keys.ps1 -EnvFile .env -DeleteSource`
(DPAPI-protected, current user only; without keys the pipeline still works —
reputation answers `no_key`).

## What it downloads / what leaves the machine

- Downloads: winget packages above + npm deps for the local MCP server. Tier 2
  spends Claude API usage per escalation (typically a few cents; hard-bounded
  by the 3-min cap and 25-turn limit).
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

Week 1: review `state\proposals.jsonl` (entries marked `double_clean` first)
and promote good ones into `whitelist.json` by hand — suppression alone
expires every 24 h. The seed whitelist is deliberately narrow; expect a small
burst of one-time CLEANs until it learns your environment.

## Honest limitations

- SNI is captured only on ports 443/8443 (`sni.capture_ports`,
  config-extendable); TLS on odd ports rides on DNS attribution or escalates
  unattributed.
- If both attribution sources go down, a flood guard stops Tier-2 spam and
  raises one urgent toast instead.
- Deleting an alarm's `*-open.marker` file is how a human closes an
  investigation and re-arms escalation for those connections.

## Tests

`pwsh -NoProfile -File tests\run-tests.ps1` — self-contained harness, no
Pester, no admin, no live Claude calls (Tier 2 is stubbed).

## License

MIT (see `LICENSE`).
