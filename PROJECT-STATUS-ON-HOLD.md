# netwatch — status on hold (2026-09-27)

The project is paused. This file lists everything known to be required
before netwatch could be trusted, so work can resume from here.

Evidence labels: **VERIFIED** = reproduced or traced exactly in code/CI;
**UNVERIFIED** = depends on live Windows / Claude CLI behaviour not observed.

---

## 0. Context

- The machine netwatch was built and tuned on was running a RAT that created
  local users and privileges and used npm packages, WinSxS substitution
  (DLL side-loading) and `msedgewebview2`. That machine has been reinstalled.
- Every trust decision taken from its observations (seed whitelist, browser
  list, Tier-2 prompt "machine context", Tier-3 `auto` mode) is unverified.
- Repo audit (2026-09-27): no injected malicious code found — npm
  dependencies match registry hashes (current and original lockfiles), no
  hidden characters/blobs/binaries, network calls only to documented
  endpoints, no persistence/account/evasion primitives, first 8 commits
  (author `netwatch-implementer`, 2026-08-28/29) contain no
  exfiltration/persistence code. What they DID contain is a cluster of
  detection-weakening settings (see §2).

## 1. Where the work stands

| Item | State |
|---|---|
| main (`798b087`) | PRs #1–#4 merged: guard hardening, identity pins, Sysmon source, path policy, fail-closed ledger, ops/CI hardening |
| branch `claude/post-compromise` (`de59dcc`, `dd54f9d`) | NOT merged; PR #5 closed. Contains the post-compromise reset (§2) — the starting point if work resumes |
| Windows CI | green on main; PR #5 run not evaluated |

**main still contains the compromised-era trust** (seed whitelist, browser
list incl. `msedgewebview2`, owner-profile prompt, Tier-3 `auto`). Do not
deploy main.

## 2. Done on `claude/post-compromise` (not in main)

- Seed whitelist shipped empty; old entries only as scrubbed synthetic test
  fixture (`tests/fixtures/whitelist.fixture.json`).
- `browser_attributed_ok` default empty; runtimes that any program can drive
  (`msedgewebview2`, `node`, script hosts, …) never get browser credit.
- Tier-2 prompt: owner profile removed ("pentester workstation", "cheap
  VPS/reputation are weak because the owner's C2 looks like that",
  "exploit tooling is normal"). Reputation/hosting ASN/missing attribution
  are signals; `mismatch` always suspicious; unsigned always hashed;
  runtimes judged by host process; `do-log` is a forgeable local claim.
- Tier 3: `--permission-mode default` (was `auto`); connection keys no
  longer inlined in its prompt; session id only if GUID-shaped.
- Domain whitelist matches require a DNS-backed name (forged SNI/Host no
  longer whitelists — VERIFIED exploit before the fix).
- `init-deploy.ps1 -ResetTrust`; `verify-packages.ps1` fails closed;
  DNS ETW per-IP domain cap; DECISIONS D12.

## 3. Blocking architecture problem (decision needed before anything else)

**The elevated Tier-1 task executes and trusts files an unprivileged
process can write.** (VERIFIED in code; live exploitation UNVERIFIED.)

- `install/register-task.ps1` runs at `RunLevel Highest`, entry script in the
  user-owned repo dir; modules, config, `mcp-config.json`, `server.mjs`,
  `node_modules` are user-writable.
- `claude_exe 'auto'` resolves from PATH (`%APPDATA%\npm\claude.cmd`);
  example config points to `%USERPROFILE%\.local\bin\claude.exe`.
- Claude CLI runs with cwd = state root and reads `~/.claude` settings,
  hooks, `CLAUDE.md` — no `--restricted` / setting-source isolation
  (CLI 2.1.283 has `--restricted`, `--setting-sources`, `--settings`, `--bare`).
- State in `%LOCALAPPDATA%\netwatch` is user-writable: `suppression.json`
  (uncapped expiry), `alarms/*-open.marker` (permanent exclusion),
  `state/sysmon-bookmark.xml` (skip events), `escalations/*-verdict.json`
  (re-read without re-validation, `escalate.psm1:141,148`), `apikeys.dat`
  (DPAPI CurrentUser — any same-user code decrypts).
- User module path precedes `$PSHOME` even with `-NoProfile` → a planted
  `NetTCPIP`/`BurntToast` module shadows cmdlets (VERIFIED on Linux pwsh).
- BurntToast installed `-Scope CurrentUser`, runs in the elevated task.

Impact: a user-level RAT gets admin at next logon, or silently removes its
keys from monitoring, or forges a CLEAN verdict.

Options:
1. **Everything non-elevated** (`RunLevel Limited`): removes the escalation
   path; costs more `unknown` identities (SYSTEM process paths unreadable),
   Sysmon needs Event Log Readers, Npcap non-admin mode; a same-user RAT can
   still tamper with netwatch state.
2. **Privilege separation** (recommended for this threat model): collector as
   SYSTEM from admin-only ACL'd dirs (Program Files + ProgramData), state
   there; Claude (Tier 2/3) as the unprivileged user with `--restricted`;
   verdict returned over a channel and re-validated by the collector;
   modules imported by absolute path.

Hard limit: an attacker with admin on the same machine can defeat any
on-host monitor.

## 4. Verified defects still open (fix in any architecture)

### Tier 2 / Tier 3
- `check-signature.ps1:140` `msix_context` = regex `\WindowsApps\` anywhere →
  `%TEMP%\WindowsApps\rat.exe` counts as MSIX, NotSigned "expected",
  hash skipped. Anchor to `%ProgramFiles%\WindowsApps\`. VERIFIED.
- `escalate.psm1:273,292` + `launch-tier3.ps1:42`: keys joined/split on `,`;
  process named `upd,x.exe` escapes its alarm marker and gets suppressed
  24 h with a false "operator resolution" log. Pass keys as JSON/file. VERIFIED.
- `launch-tier3.ps1:101-110`: watchdog `Start-Process -ArgumentList` joins on
  spaces → a key with spaces/`-Param` breaks the watchdog. VERIFIED.
- `invoke-tier2.ps1:77`: quota detection matches text "session limit" alone
  (comment says status 429); outcome 6 = no Tier 3. Require 429; repeated
  quota failures with a pending queue must escalate. VERIFIED.
- Proposals (`invoke-tier2.ps1:154-161`, whitelist schema) unbounded:
  `domain_suffixes:["com"]`, `cidrs:["0.0.0.0/0"]`, no processes all valid.
  Bind proposals to the key's process + destination. VERIFIED.
- Timeout salvage (`invoke-tier2.ps1:276-293`) can rebuild ALARM with all
  connections `clean` as CLEAN. VERIFIED (trace).
- Prompt: SNI described as "on the wire" — it is client-written like Host;
  require ASN/IP consistency with the claimed domain; always call
  reputation on hosting/VPS ASNs. VERIFIED (text).
- Lineage (`check-process-lineage.ps1:105-125`): no PID start-time binding
  (packet lacks it), parent walk does not check parent-older-than-child,
  PPID spoofing; prompt must say lineage can be forged. VERIFIED (code).
- Own-IP guard knows only the OpenDNS-seen IPv6 address, not the host /64.
  UNVERIFIED live.
- AbuseIPDB has no per-minute cap → injected call loop drains daily quota.
  UNVERIFIED.

### Tier 1
- Identity pins in `%LOCALAPPDATA%` (Edge SxS, per-user EdgeWebView) are
  user-writable → copy genuine signed exe + planted DLL = `verified`;
  `-like '*'` spans `\` (any depth). Admin-only roots, single-segment `*`.
  VERIFIED.
- Signer cache key `path|mtime|size` survives a same-size/mtime swap in
  writable pin dirs. Traced.
- Residual/suppression key `name|dest|port` ignores identity: an impostor
  (`mismatch`) shares the real process's key, inherits its CLEAN
  suppression / alarm marker. VERIFIED.
- Sleep/resume rebaseline (`netwatch.ps1:88`) sets `samples=0`; stale key
  escalates at 60 s age, packet schema requires `samples_seen>=1` → every
  tick throws up to 2 h. VERIFIED (run).
- Tier-2 starvation: 4 keys / 10 min, oldest-first; ~1000 junk keys delay a
  real C2 key ~40 h; flood guard stops Tier 2 above 60 keys when blind,
  `$floodToasted` never resets; immediate keys not prioritised. Traced.
- `unknown` identity trusts bare name for destination entries. Traced.
- DNS attribution is ambient (`dns-ip` = most recent name for the IP,
  `dns-cache` no PID); an attacker resolving a whitelisted name last on a
  shared CDN IP relabels its C2; attacker-chosen DNS servers/hosts file can
  "confirm" any name. Traced / design.
- DNS ETW reader has no per-tick event cap (O(n) growth measured: 11 s for
  20k events). Partially fixed on branch (per-IP cap); per-tick cap open.
- Direction from Listen-table heuristic spoofable (listen, accept, close
  listener → outbound). Traced.

### Install / CI / tests
- `enable-sysmon.ps1`: verifies signature then executes the user-supplied
  path up to 4× (swap window); `-KeepExistingConfig` never checks the
  installed binary. Copy to admin-only dir, verify, run the copy.
- `verify-packages.ps1`: Authenticode `Valid` without signer pinning; hash
  from the same download. Pin signer org; commit a hash from a trusted
  machine. (Fail-closed exit fixed on branch.)
- CI installs `@anthropic-ai/claude-code@latest` globally with install
  scripts; pin version or drop (suite never calls it). Dependabot without
  cooldown.
- `probe-environment.ps1` `mcp_deps: ok` checks tree presence, not file
  integrity in user-writable `node_modules`.
- Harness: `_assert.ps1` trap never fires when dot-sourced (exit code still
  correct); `Skip-Test` inside try/catch is swallowed; `enrich.tests.ps1`
  live Cymru and `mainloop.tests.ps1` "no residuals" print WARNING instead of
  `Skip-Test`; `Assert-Throws` passes on any exception; mainloop/e2e tests
  make live OpenDNS/Cymru lookups; test roots under the live state root.

### Docs (stale on main)
- ARCHITECTURE: seed "GOAL baseline", Tier-3 prompt "affected keys",
  admin-required vs README non-elevated; DONE: `claude --resume` window,
  seed baseline; DECISIONS/launch-tier3/watchdog: "PreToolUse jail hooks"
  that do not exist in the repo (Tier 3 is NOT jailed);
  README_AGENTS_AI lists D1–D8 only.

## 5. Design limits (not bugs; decide whether to accept)

- **TCP only.** UDP/QUIC and DNS tunnelling are invisible to Tier 1
  (Sysmon config was made TCP-only — reconsider).
- **DLL side-loading / injection invisible.** Identity = exe path + signer.
  Candidate: Sysmon event 7 (unsigned image load), 8 (CreateRemoteThread),
  10 (process access) feeding identity → `mismatch`.
- **C2 over trusted services** (Telegram, GitHub, Discord, cloud storage)
  passes once such a destination is whitelisted for any process that can
  be injected.
- **Tier-2 verdict is an LLM judgment** over attacker-shaped data.
- netwatch is not an EDR; keep Defender (with ASR rules) as the primary
  host control.

## 6. Manual verification on a real Windows 11 (never done)

- `check-signature`/`hash-file` on `WindowsApps` executables as a standard
  user (CI runner is admin).
- Whether Authenticode verification makes network requests (AIA/CDP).
- Real image paths/signers of pinned processes (svchost, msedge, WebView2,
  MsMpEng, SearchHost, OfficeClickToRun…).
- CIM `ExecutablePath` readability under the task's actual privilege.
- One live Tier-2 run on a synthetic packet.
- Sysmon first-install behaviour on Windows 11 (retry path added for the
  Server-image failure `wevtutil.exe returned failure`, exit 13).

## 7. Outside the repo (owner)

- Rotate everything reachable from the compromised machine: GitHub password,
  2FA, PATs, SSH keys; review GitHub security log, OAuth apps, deploy keys,
  webhooks; Claude/Anthropic login and API keys; npm tokens;
  VirusTotal/AbuseIPDB keys.
- Global npm packages installed on that machine (e.g. `pi-coding-agent`,
  `@anthropic-ai/claude-code`) were outside this audit.
- Repository visibility: set to private (GitHub → Settings → General →
  Danger Zone → Change visibility).
