# netwatch — architecture pass DONE (2026-08-26)

One-page summary. Full detail: ARCHITECTURE.md, DECISIONS.md,
TIER2-CONTRACT.md, FAILURE-MATRIX.md.

## What was decided

- **Tier 1** (pwsh 7, logon scheduled task, mutex-guarded): 30-s TCP
  sampling; domain attribution = ETW DNS-Client (bookmarked 3006/3008) +
  tshark SNI (443/8443, supervised with backoff); domain-based whitelist
  with CIDR fallback; browser policy (attributed msedge/webview2 traffic =
  clean-log, raw-IP browser traffic stays escalatable); Cymru ASN on
  residual only; own-IP exclusion fail-closed (detected + last-known +
  recorded 203.0.113.10).
- **Escalation**: debounce = seen in >= 2 samples OR >= 60 s old; Tier-2
  spacing 10 min; immediate bypass for unclassified inbound and
  deleted-image processes; 20-key batch cap; 24-h suppression after CLEAN.
- **Tier 2** = `claude -p --model sonnet --output-format json`, system
  prompt replaced, `--strict-mcp-config` + `--permission-mode dontAsk` +
  explicit `--disallowedTools` for all built-ins; ONLY four read-only MCP
  tools (check_signature / hash_file / check_reputation /
  check_process_lineage) served by a Node stdio MCP server (SDK v2) that
  shells to fixed .ps1 files via `pwsh -File`. Reputation lookups live
  only here, quota-guarded, own-IP guard not model-overridable.
- **3-min cap**: System.Diagnostics.Process + WaitForExit(180000) +
  Kill($true) (whole tree); packet via stdin (no argv quoting hazards).
- **CLEAN**: BurntToast toast (>= 1.1.0, pwsh-7-compatible path verified)
  + suppression + whitelist PROPOSAL only — permanence requires
  human/Tier-3 confirmation (prompt-injection containment).
- **ALARM/timeout/failure**: urgent toast + visible
  `claude --resume <session_id>` window (headless sessions are not
  reachable via `--continue` — doc-verified); fallback fresh session on
  early Tier-2 death.
- **Retention**: conn/op logs 14 d, escalations 90 d, alarms 365 d, daily
  housekeeping.

## Where each part lives

| Artifact | File |
|---|---|
| Build architecture, module map | `ARCHITECTURE.md` |
| Open-item resolutions D1–D8 | `DECISIONS.md` |
| Tier-2 tool surface + invocation + verdict contract | `TIER2-CONTRACT.md` |
| Fixed Tier-2 prompt | `prompts/tier2-system-prompt.md` |
| Edge cases F1–F24 | `FAILURE-MATRIX.md` |
| Schemas (whitelist / packet / verdict / config) | `schemas/*.json` |
| Seed whitelist (GOAL baseline) + example config | `config/` |
| Implementation (collector, cap launcher, toast, tier3, 4 tools, MCP server) | `src/` (the design-pass skeletons were removed once superseded) |

## Open risks (for the implementer)

1. `connect_monitor.ps1` POC was not on disk — Tier-1 collector designed
   from the GOAL text alone; reconcile if the POC surfaces.
2. Verify at deploy: installed claude CLI supports the exact flags
   (`--system-prompt-file` used since 2026-09-26 - the inline string form
   overflowed cmd.exe's command-line limit); `--permission-mode dontAsk` semantics on the installed
   version; BurntToast `-Urgent`-equivalent parameter name in 1.1.0.
3. Inbound-direction detection from Get-NetTCPConnection needs the
   Listen-table heuristic implemented carefully (false "inbound" would
   spam immediate escalations).
4. MS whitelist seeds are deliberately narrow (no broad Azure CIDRs) —
   expect a burst of one-time Tier-2 CLEANs in week 1 that a human should
   convert into whitelist entries from proposals.jsonl.
5. tshark sees only configured ports (443/8443) — TLS on odd ports rides
   on DNS attribution or escalates unattributed (accepted limitation).
