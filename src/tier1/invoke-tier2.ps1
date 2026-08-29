# invoke-tier2.ps1 - launch headless Tier-2 claude with the hard wall-clock
# cap. Mechanism per DECISIONS D3: System.Diagnostics.Process +
# WaitForExit(ms) + Kill($true) (kills the whole descendant tree: claude.exe
# -> node.exe children -> MCP server). pwsh 7 only.
#
# Usage: pwsh -File invoke-tier2.ps1 -PacketPath <escalations\ts-packet.json>
#          -ConfigPath <netwatch.config.json>
# Exit codes: 0 = verdict validated + written (incl. a COMPLETE verdict
#                 salvaged from a timed-out run, DECISIONS D9),
#             2 = timeout with nothing salvageable (tree killed),
#             3 = launch failure, 4 = bad/invalid output (caller retries once),
#             5 = timeout with a PARTIAL salvaged verdict: verdict.json carries
#                 the validated connections + uncovered_keys for Tier-3.
#             6 = subscription session quota exhausted (HTTP 429 from the
#                 claude.ai backend, live 2026-08-28: "session limit · resets
#                 ...") - caller must NOT retry immediately (an instant retry
#                 into an exhausted quota just burns the second F2 attempt on
#                 the same 429) and must NOT escalate to Tier 3 (capacity, not
#                 a finding).

#Requires -Version 7
param(
    [Parameter(Mandatory)] [string]$PacketPath,
    [Parameter(Mandatory)] [string]$ConfigPath,
    [int]$Attempt = 1     # F2 retry attempt; keeps each attempt's raw output in the audit trail
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules\state.psm1') -Force

$cfg       = Get-NetwatchConfig -Path $ConfigPath
$capMs     = 1000 * $cfg.tier2.wall_clock_cap_sec
$stateRoot = $cfg.paths.state_root
$codeRoot  = $cfg.paths.code_root
$ts        = [IO.Path]::GetFileName($PacketPath) -replace '-packet\.json$', ''
$outDir    = Join-Path $stateRoot 'escalations'
$attemptSuffix = if ($Attempt -gt 1) { "-r$Attempt" } else { '' }

$allowed = @(
    'mcp__netwatch__check_signature'
    'mcp__netwatch__hash_file'
    'mcp__netwatch__check_reputation'
    'mcp__netwatch__check_process_lineage'
) -join ','
$denied = 'Bash,Read,Write,Edit,NotebookEdit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite'

$packetRaw  = Get-Content -LiteralPath $PacketPath -Raw
$packetKeys = @(($packetRaw | ConvertFrom-Json).connections | ForEach-Object key)

# --- helpers (defined before the timeout path can need them) -----------------

# Diagnosis snippet for failed attempts: each retry re-bills the whole batch,
# so the op-log must say WHY an attempt died (live 2026-08-27: 17:55Z 'API
# Error: Connection lost mid-response' was only visible by opening stdout.json)
function Get-StdoutSnippet {
    param([string]$Text)
    $s = ($Text -replace '\s+', ' ').Trim()
    if ($s.Length -gt 200) { $s = $s.Substring(0, 200) }
    return $s
}

# Detects the claude.ai subscription session-quota rejection (live
# 2026-08-28: two escalations each burned both F2 attempts on this in ~2s,
# then falsely escalated to Tier 3 as tier2_failed - a 429 is a capacity
# signal, never a verdict). Structured field first (api_error_status), text
# match only as corroboration - never classify on text alone.
function Test-QuotaExhausted {
    param([string]$Text)
    try { $envelope = $Text | ConvertFrom-Json } catch { return $null }
    # empty/whitespace stdout (e.g. a crash before any output) converts to
    # $null without throwing - StrictMode then faults on the property access
    if ($null -eq $envelope) { return $null }
    if (-not $envelope.PSObject.Properties['is_error'] -or -not $envelope.is_error) { return $null }
    $status = if ($envelope.PSObject.Properties['api_error_status']) { $envelope.api_error_status } else { $null }
    $resultText = [string]$envelope.result
    if ($status -eq 429 -or $resultText -match '(?i)session limit') {
        return "api_error_status=$status result=$(Get-StdoutSnippet $resultText)"
    }
    return $null
}

function ConvertFrom-Tier2Stdout {
    # envelope JSON -> @{ envelope; verdict } or $null. Includes the
    # markdown-fence unwrap (observed live 2026-08-27).
    param([string]$Text)
    try {
        $envelope = $Text | ConvertFrom-Json
        $resultText = ([string]$envelope.result).Trim()
        if ($resultText -match '(?s)^```[a-zA-Z]*\s*(.*?)\s*```$') { $resultText = $Matches[1] }
        return @{ envelope = $envelope; verdict = ($resultText | ConvertFrom-Json) }
    }
    catch { return $null }
}

function Test-ConnectionShape {
    # One verdict connection valid on its own? Used by the full-shape check
    # and by per-connection salvage (D9: never treat unvalidated as clean).
    param($C)
    foreach ($f in 'key', 'assessment', 'reasons', 'evidence') {
        if (-not $C.PSObject.Properties[$f]) { return $false }
    }
    if ($C.assessment -notin 'clean', 'suspicious') { return $false }
    if (@($C.reasons).Count -lt 1) { return $false }
    return $true
}

function Test-VerdictSchema {
    # Test-Json against schemas/verdict.schema.json (reviewer M1: the schema
    # existed but was unparseable and never applied - type errors like a
    # numeric summary slipped through). Complements Test-VerdictShape, which
    # does what a schema cannot: key-set matching and suspicious=>ALARM.
    param($Verdict)
    $schema = Join-Path $codeRoot 'schemas\verdict.schema.json'
    $json = $Verdict | ConvertTo-Json -Depth 10
    return [bool](Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue)
}

function Test-VerdictShape {
    param($Verdict, [string[]]$ExpectedKeys)
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($f in 'verdict', 'connections', 'summary') {
        if (-not $Verdict.PSObject.Properties[$f]) { $errors.Add("missing field $f") }
    }
    if ($errors.Count) { return $errors }
    if ($Verdict.verdict -notin 'CLEAN', 'ALARM') { $errors.Add("bad verdict value '$($Verdict.verdict)'") }
    $seen = @()
    $anySuspicious = $false
    foreach ($c in @($Verdict.connections)) {
        foreach ($f in 'key', 'assessment', 'reasons', 'evidence') {
            if (-not $c.PSObject.Properties[$f]) { $errors.Add("connection missing $f"); continue }
        }
        if (-not $c.PSObject.Properties['key']) { continue }
        $seen += $c.key
        if ($c.PSObject.Properties['assessment']) {
            if ($c.assessment -notin 'clean', 'suspicious') { $errors.Add("bad assessment '$($c.assessment)' for $($c.key)") }
            if ($c.assessment -eq 'suspicious') { $anySuspicious = $true }
        }
        if ($c.PSObject.Properties['reasons'] -and @($c.reasons).Count -lt 1) { $errors.Add("empty reasons for $($c.key)") }
    }
    # F24: exact key-set match - no dropped keys, no invented keys
    foreach ($k in $ExpectedKeys) { if ($k -notin $seen) { $errors.Add("packet key not answered: $k") } }
    foreach ($k in $seen)         { if ($k -notin $ExpectedKeys) { $errors.Add("unknown key in verdict: $k") } }
    if ($anySuspicious -and $Verdict.verdict -ne 'ALARM') { $errors.Add('suspicious connection but verdict not ALARM') }
    return $errors
}

function Write-VerdictFile {
    # Proposal validation + verdict.json write, shared by the normal path and
    # both salvage outcomes. salvaged/uncovered_keys appear ONLY on partial
    # salvage so normal consumers see the unchanged shape.
    param($Envelope, $Verdict, [string[]]$UncoveredKeys = @())
    $wlSchema = Join-Path $codeRoot 'schemas\whitelist.schema.json'
    foreach ($c in @($Verdict.connections)) {
        if ($c.PSObject.Properties['proposed_whitelist_entry'] -and $c.proposed_whitelist_entry) {
            $wrapped = @{ version = 1; entries = @($c.proposed_whitelist_entry) } | ConvertTo-Json -Depth 10
            if (-not (Test-Json -Json $wrapped -SchemaFile $wlSchema -ErrorAction SilentlyContinue)) {
                Write-OpLog -Config $cfg -Level WARN -Message "dropping schema-invalid proposal for $($c.key)"
                $c.PSObject.Properties.Remove('proposed_whitelist_entry')
            }
        }
    }
    $sessionId = if ($Envelope -and $Envelope.PSObject.Properties['session_id']) { $Envelope.session_id } else { $null }
    $doc = [ordered]@{
        session_id = $sessionId                                    # tier3 reference
        verdict    = $Verdict
    }
    if ($UncoveredKeys.Count) {
        $doc.salvaged       = $true
        $doc.uncovered_keys = @($UncoveredKeys)
    }
    [pscustomobject]$doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outDir "$ts-verdict.json")
}

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = $cfg.tier2.claude_exe
$psi.WorkingDirectory       = $stateRoot            # session files live here, not in repo
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute        = $false
# System prompt: --system-prompt takes a STRING (replace-from-file flag is not
# doc-confirmed) -> load the fixed prompt here. ArgumentList = one argv entry
# per element, no shell quoting involved.
$sysPrompt = Get-Content -LiteralPath (Join-Path $codeRoot 'src\tier2\system-prompt.md') -Raw
foreach ($a in @($cfg.tier2.claude_args_prefix) + @(
        '-p', 'Analyze the escalation packet provided on stdin per your system prompt.',
        '--model', $cfg.tier2.model,
        '--output-format', 'json',
        '--system-prompt', $sysPrompt,
        '--mcp-config', (Join-Path $codeRoot 'src\tier2\mcp-config.json'),
        '--strict-mcp-config',
        '--permission-mode', 'dontAsk',
        '--allowedTools', $allowed,
        '--disallowedTools', $denied,
        '--max-turns', "$($cfg.tier2.max_turns)"
    )) { if ($null -ne $a) { $psi.ArgumentList.Add($a) } }

# API keys for the MCP tools: DPAPI store -> child env only; never argv/logs.
$psi.Environment['NETWATCH_STATE'] = $stateRoot
$psi.Environment['NETWATCH_PWSH']  = (Get-Command pwsh).Source
$psi.Environment['NETWATCH_VT_PER_DAY']    = "$($cfg.reputation_quota.vt_per_day)"
$psi.Environment['NETWATCH_VT_PER_MIN']    = "$($cfg.reputation_quota.vt_per_min)"
$psi.Environment['NETWATCH_ABUSE_PER_DAY'] = "$($cfg.reputation_quota.abuseipdb_per_day)"
$keyFile = Join-Path $stateRoot 'state\apikeys.dat'
if (Test-Path -LiteralPath $keyFile) {
    try {
        $enc = [IO.File]::ReadAllBytes($keyFile)
        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $keys = [Text.Encoding]::UTF8.GetString($dec) | ConvertFrom-Json
        if ($keys.abuseipdb) { $psi.Environment['ABUSEIPDB_KEY'] = $keys.abuseipdb }
        if ($keys.vt)        { $psi.Environment['VT_KEY']        = $keys.vt }
        # presence by NAME only, never values (live 2026-08-27: vt was silently
        # null in the store and every reputation answer carried vt no_key with
        # nothing in the op-log to explain why)
        Write-OpLog -Config $cfg -Level INFO -Message "apikeys loaded: abuseipdb=$([bool]$keys.abuseipdb) vt=$([bool]$keys.vt)"
    }
    catch {
        Write-OpLog -Config $cfg -Level WARN -Message "apikeys.dat unreadable, reputation runs keyless: $($_.Exception.Message)"
    }
}
else {
    Write-OpLog -Config $cfg -Level WARN -Message 'apikeys.dat missing - reputation runs keyless'
}

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi
try { $null = $proc.Start() } catch { exit 3 }                    # F3

# Async drains BEFORE stdin write - avoids pipe-buffer deadlock on big output.
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()

$proc.StandardInput.Write($packetRaw)                              # packet = prompt body
$proc.StandardInput.Close()

if (-not $proc.WaitForExit($capMs)) {
    # HARD CAP HIT: kill entire tree (claude + node children + MCP server).
    try { $proc.Kill($true) } catch {}
    $proc.WaitForExit()                                            # reap
    $salvagedText = $stdoutTask.Result
    try { Set-Content -LiteralPath (Join-Path $outDir "$ts-stderr$attemptSuffix.txt") -Value $stderrTask.Result } catch {}
    # salvage whatever stdout arrived before the kill - the timeout runs of
    # 2026-08-27 left no output artifact at all, blinding the post-mortem
    try { Set-Content -LiteralPath (Join-Path $outDir "$ts-stdout$attemptSuffix-partial.json") -Value $salvagedText } catch {}

    # D9 (operator-approved 2026-08-28): the kill may land AFTER the analysis
    # finished (live 20260828-103245-317: full valid 6-key verdict in the
    # salvaged stdout at 182s vs the 180s cap - discarded, all 6 raised
    # tier3). A COMPLETE valid verdict is a finished analysis - accept it.
    # A partially valid one applies per validated connection only; nothing
    # unvalidated is ever treated as clean, the rest keep the F1 path.
    $parsed = ConvertFrom-Tier2Stdout -Text $salvagedText
    if ($parsed -and $null -ne $parsed.verdict) {
        $v = $parsed.verdict
        if (-not @(Test-VerdictShape -Verdict $v -ExpectedKeys $packetKeys).Count -and (Test-VerdictSchema $v)) {
            Write-OpLog -Config $cfg -Level INFO -Message "tier2 timeout but salvaged stdout holds a complete valid verdict - accepted (D9, attempt $Attempt)"
            Write-VerdictFile -Envelope $parsed.envelope -Verdict $v
            exit 0
        }
        if ($v.PSObject.Properties['connections']) {
            $seenKeys = @{}
            $valid = @(@($v.connections) | Where-Object {
                    (Test-ConnectionShape $_) -and $_.key -in $packetKeys -and
                    -not $seenKeys.ContainsKey($_.key) -and ($seenKeys[$_.key] = $true)
                })
            if ($valid.Count -and (Test-VerdictSchema ([pscustomobject]@{
                        verdict = 'CLEAN'; connections = $valid; summary = 'salvage-precheck' }))) {
                $covered   = @($valid | ForEach-Object key)
                $uncovered = @($packetKeys | Where-Object { $_ -notin $covered })
                $summary   = if ($v.PSObject.Properties['summary'] -and $v.summary) { [string]$v.summary } else { '' }
                $newVerdict = [pscustomobject]@{
                    verdict     = if (@($valid | Where-Object assessment -eq 'suspicious').Count) { 'ALARM' } else { 'CLEAN' }
                    connections = $valid
                    summary     = "salvaged after timeout ($($valid.Count)/$($packetKeys.Count) keys): $summary"
                }
                if (-not $uncovered.Count) {
                    # every key individually valid, only the AGGREGATE shape was
                    # broken (e.g. missing summary) - the rebuilt verdict is
                    # complete, accept it as a normal run (reviewer M2: exit 5
                    # with empty uncovered_keys crashed the caller)
                    Write-OpLog -Config $cfg -Level INFO -Message "tier2 timeout: salvage covers every key, rebuilt verdict accepted as complete (D9, attempt $Attempt)"
                    Write-VerdictFile -Envelope $parsed.envelope -Verdict $newVerdict
                    exit 0
                }
                Write-OpLog -Config $cfg -Level WARN -Message "tier2 timeout: partial verdict salvaged, $($valid.Count)/$($packetKeys.Count) keys covered (D9, attempt $Attempt)"
                Write-VerdictFile -Envelope $parsed.envelope -Verdict $newVerdict -UncoveredKeys $uncovered
                exit 5
            }
        }
    }
    exit 2                                                         # F1 -> caller triggers Tier 3
}

$stdout = $stdoutTask.Result
Set-Content -LiteralPath (Join-Path $outDir "$ts-stdout$attemptSuffix.json") -Value $stdout
Set-Content -LiteralPath (Join-Path $outDir "$ts-stderr$attemptSuffix.txt")  -Value $stderrTask.Result

# F2: a nonzero exit is a failed run even when stdout happens to parse -
# UNLESS it is the subscription quota rejection (F2's blind retry is exactly
# wrong there: two attempts 2s apart both hit 429 live 2026-08-27, then
# false-escalated to Tier 3 as tier2_failed).
if ($proc.ExitCode -ne 0) {
    $quota = Test-QuotaExhausted -Text $stdout
    if ($quota) {
        Write-OpLog -Config $cfg -Level WARN -Message "tier2 quota exhausted (attempt $Attempt): $quota"
        exit 6
    }
    Write-OpLog -Config $cfg -Level WARN -Message "tier2 exited $($proc.ExitCode) (attempt $Attempt); stdout: $(Get-StdoutSnippet $stdout)"
    exit 4
}

# --- parse + validate (F2/F24) ----------------------------------------------
$parsed = ConvertFrom-Tier2Stdout -Text $stdout
if (-not $parsed) {
    Write-OpLog -Config $cfg -Level WARN -Message "tier2 output unparsable (attempt $Attempt): $(Get-StdoutSnippet $stdout)"
    exit 4                                                         # F2 -> caller retries once
}
$verdict = $parsed.verdict

if (-not (Test-VerdictSchema $verdict)) {
    Write-OpLog -Config $cfg -Level ERROR -Message "tier2 verdict fails verdict.schema.json (attempt $Attempt)"
    exit 4
}
$problems = @(Test-VerdictShape -Verdict $verdict -ExpectedKeys $packetKeys)
if ($problems.Count) {
    Write-OpLog -Config $cfg -Level ERROR -Message "tier2 verdict invalid: $($problems -join '; ')"
    exit 4
}

Write-VerdictFile -Envelope $parsed.envelope -Verdict $verdict
exit 0
