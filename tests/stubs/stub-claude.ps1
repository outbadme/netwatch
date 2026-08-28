# stub-claude.ps1 - test double for the headless Tier-2 claude CLI.
# Reads the escalation packet from stdin (like the real CLI) and emits a
# --output-format json envelope. Behavior via env STUB_MODE:
#   clean   - valid CLEAN verdict echoing all packet keys (+1 proposal)
#   alarm   - valid ALARM verdict (first key suspicious)
#   garbage - non-JSON stdout
#   dropkey - valid-looking CLEAN verdict that omits the last packet key (F24)
#   hang    - spawns a sleeping child (pid -> STUB_CHILD_PIDFILE), then sleeps
#             far past the cap: exercises Kill(true) tree termination (F1)
#   hangafter    - prints a COMPLETE valid CLEAN envelope, flushes, then hangs:
#             the live 20260828-103245-317 case (analysis finished, exit never
#             came) - salvage must accept the full verdict (D9)
#   hangpartial  - prints an envelope whose verdict covers ONLY the first
#             packet key, flushes, then hangs: per-connection salvage
#   hangnosummary - all keys individually valid but the aggregate shape fails
#             (summary missing), then hangs: full per-connection coverage with
#             zero uncovered keys (reviewer finding M2, 2026-08-28)
#   crash   - exit 1, no output
#   cleanfail - valid CLEAN envelope but exit 1 (F2: nonzero exit = failed run)
#   fenced  - valid CLEAN verdict wrapped in markdown code fences inside the
#             envelope result (observed live 2026-08-27: sonnet sometimes
#             fences the JSON despite the prompt; parser must unwrap)
#   badproposal - valid CLEAN verdict whose proposed_whitelist_entry is
#             shape-invalid (observed live 2026-08-27 17:55:33Z); launcher
#             must drop the proposal and keep the verdict
# STUB_COUNT_FILE (optional): invocation counter for retry tests.
param()
$ErrorActionPreference = 'Stop'

if ($env:STUB_COUNT_FILE) {
    $n = if (Test-Path $env:STUB_COUNT_FILE) { [int](Get-Content $env:STUB_COUNT_FILE) } else { 0 }
    Set-Content -LiteralPath $env:STUB_COUNT_FILE -Value ($n + 1)
}

$mode = $env:STUB_MODE
if (-not $mode) { $mode = 'clean' }

if ($mode -eq 'crash') { exit 1 }
if ($mode -eq 'garbage') { Write-Output 'this is not json at all {{{'; exit 0 }

$stdin = [Console]::In.ReadToEnd()
$packet = $stdin | ConvertFrom-Json
$keys = @($packet.connections | ForEach-Object key)

if ($mode -eq 'hang') {
    $sleeper = Join-Path $PSScriptRoot 'sleeper.ps1'
    Start-Process -FilePath (Get-Command pwsh).Source `
        -ArgumentList @('-NoProfile', '-File', $sleeper, '-PidFile', $env:STUB_CHILD_PIDFILE) `
        -WindowStyle Hidden
    Start-Sleep -Seconds 120
    exit 0
}

if ($mode -eq 'dropkey') { $keys = @($keys | Select-Object -SkipLast 1) }
if ($mode -eq 'hangpartial') { $keys = @($keys | Select-Object -First 1) }

$connections = @()
$first = $true
foreach ($k in $keys) {
    $c = [ordered]@{
        key        = $k
        assessment = if ($mode -eq 'alarm' -and $first) { 'suspicious' } else { 'clean' }
        reasons    = @(if ($mode -eq 'alarm' -and $first) { 'stub: simulated suspicious finding' } else { 'stub: simulated clean' })
        evidence   = @('stub-tool: simulated evidence')
    }
    if ($mode -ne 'alarm' -and $first) {
        $c.proposed_whitelist_entry = if ($mode -eq 'badproposal') {
            [ordered]@{ bogus = 'no id, no match - fails whitelist schema' }
        }
        else {
            [ordered]@{
                id       = 'stub-proposal'
                match    = @{ domains = @('stub.example.com'); processes = @('stubproc') }
                added_by = 'tier3'
                added_at = [datetime]::UtcNow.ToString('o')
                evidence = 'stub proposal for testing'
            }
        }
    }
    $connections += [pscustomobject]$c
    $first = $false
}
$verdict = [ordered]@{
    verdict     = if ($mode -eq 'alarm') { 'ALARM' } else { 'CLEAN' }
    connections = $connections
    summary     = "stub verdict in mode $mode"
}
if ($mode -eq 'hangnosummary') { $verdict.Remove('summary') }
if ($mode -eq 'badsummary')    { $verdict.summary = 12345 }   # type-invalid: schema gate must reject
$resultText = $verdict | ConvertTo-Json -Depth 10 -Compress
if ($mode -eq 'fenced') {
    $resultText = "``````json`n$resultText`n``````"
}
$envelope = [ordered]@{
    type       = 'result'
    result     = $resultText
    session_id = 'stub-session-123'
}
if ($mode -in 'hangafter', 'hangpartial', 'hangnosummary') {
    # print, force the redirected pipe flushed, then never exit - the parent's
    # wall clock must kill us with the envelope already salvageable
    [Console]::Out.Write(($envelope | ConvertTo-Json -Depth 5 -Compress))
    [Console]::Out.Flush()
    Start-Sleep -Seconds 120
    exit 0
}
$envelope | ConvertTo-Json -Depth 5 -Compress
if ($mode -eq 'cleanfail') { exit 1 }
exit 0
