# verify-http80-attribution.ps1 - positive control for port-80 Host-header
# attribution (deploy-verify pattern). Runs the pipeline against a TEMP
# state root inside the repo (never the live %LOCALAPPDATA% root, never the
# live scheduled task), holds a real plaintext HTTP connection to a public
# CRL host open across several sampling ticks, then greps the temp artifacts
# for source=http-host. Tier 2 is the test stub (STUB_MODE=clean, zero cost).
# Exit 0 = attribution proven; 2 = pipeline ran but no http-host evidence
# (report honestly, do not claim success); 1 = setup failure.

#Requires -Version 7.4
param(
    [string]$ControlHost = 'yr1.c.lencr.org',
    [string]$ControlPath = '/55.crl',
    [int]$Ticks = 6,
    [int]$DelaySec = 10,
    [string]$StateRoot = '',    # override for -ScanOnly / reruns
    [switch]$ScanOnly           # skip the pipeline, scan existing artifacts
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $StateRoot) { $StateRoot = Join-Path $repo 'tmp-deploy-verify' }

if (-not $ScanOnly) {
$null = New-Item -ItemType Directory -Force -Path $StateRoot
# evidence must be run-scoped: stale packets from an earlier control run in
# the same temp root would satisfy the scan (observed 2026-08-28) - purge
# per-file, no recursion
foreach ($old in @(Get-ChildItem (Join-Path $StateRoot 'escalations') -File -ErrorAction SilentlyContinue) +
                 @(Get-ChildItem (Join-Path $StateRoot 'logs') -File -ErrorAction SilentlyContinue)) {
    Remove-Item -LiteralPath $old.FullName -Force
}
# a suppression entry from an earlier control run (stub CLEAN, 24h TTL)
# silences the control key and yields a false NOT-PROVEN (observed
# 2026-08-28: escalatable=0 all ticks, no packet at all)
$supFile = Join-Path $StateRoot 'state\suppression.json'
if (Test-Path -LiteralPath $supFile) { Remove-Item -LiteralPath $supFile -Force }

# temp config = live config (real tshark path/interfaces) redirected to the
# temp root and the stub tier2; falls back to the example config
$srcCfg = Join-Path $repo 'config\netwatch.config.json'
if (-not (Test-Path -LiteralPath $srcCfg)) { $srcCfg = Join-Path $repo 'config\netwatch.config.example.json' }
$cfg = Get-Content -LiteralPath $srcCfg -Raw | ConvertFrom-Json
$cfg.paths.state_root = $stateRoot
$cfg.paths.code_root  = $repo
$cfg.paths | Add-Member -NotePropertyName whitelist -NotePropertyValue (Join-Path $stateRoot 'whitelist.json') -Force
$cfg.tier2.claude_exe = (Join-Path $repo 'tests\stubs\stub-claude.cmd')
# control-run tuning: escalate every eligible tick (the 10-min production
# interval would eat the control window) and ship the whole residual set
$cfg.tier2.min_interval_min = 0
$cfg.tier2 | Add-Member -NotePropertyName sec_per_key_budget -NotePropertyValue 0 -Force
$cfgPath = Join-Path $stateRoot 'config.json'
$cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $cfgPath -Encoding utf8

$env:STUB_MODE = 'clean'                 # tier2 = free stub, CLEAN verdicts
$env:NETWATCH_SUPPRESS_TOAST = '1'       # no notification-center noise

# start the pipeline (own mutex bypass: the live task may hold the real one)
$netwatch = Join-Path $repo 'src\tier1\netwatch.ps1'
$proc = Start-Process -FilePath (Get-Command pwsh).Source -PassThru -WindowStyle Hidden `
    -ArgumentList @('-NoProfile', '-File', $netwatch, '-ConfigPath', $cfgPath,
        '-MaxTicks', "$Ticks", '-TickDelaySec', "$DelaySec", '-NoMutex')

# real plaintext HTTP GET, socket held OPEN so the connection stays
# ESTABLISHED across sampling ticks (a short fetch would be missed). The GET
# is sent AFTER the first tick so the capture child is warm - request bytes
# sent before tshark starts are never seen.
Start-Sleep -Seconds ($DelaySec + 5)
$tcp = $null
try {
    $tcp = [System.Net.Sockets.TcpClient]::new($ControlHost, 80)
    $stream = $tcp.GetStream()
    $req = "GET $ControlPath HTTP/1.1`r`nHost: $ControlHost`r`nConnection: keep-alive`r`n`r`n"
    $bytes = [Text.Encoding]::ASCII.GetBytes($req)
    $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
    $buf = [byte[]]::new(4096)
    $null = $stream.Read($buf, 0, $buf.Length)   # first response chunk is enough
    Write-Host "control request sent: $ControlHost$ControlPath (socket held open)"

    $proc.WaitForExit()
}
finally {
    if ($tcp) { $tcp.Dispose() }
    Remove-Item Env:STUB_MODE, Env:NETWATCH_SUPPRESS_TOAST -ErrorAction SilentlyContinue
}
}   # end pipeline (-ScanOnly skips it)

# evidence scan: escalation packets (residual path) + conn log (clean path).
# Parsed JSON, source AND domain matched inside ONE connection - the earlier
# Select-String heuristic counted per-line hits of EITHER pattern, and the
# control host alone spans two pretty-printed lines (key + attribution
# domain), so a dns-ip packet passed the >=2 threshold (false PASS,
# reproduced 2026-08-27).
$evidence = @()
foreach ($f in @(Get-ChildItem (Join-Path $stateRoot 'escalations') -Filter '*-packet.json' -ErrorAction SilentlyContinue)) {
    $pkt = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
    foreach ($c in @($pkt.connections)) {
        if ($c.attribution.source -eq 'http-host' -and $c.attribution.domain -eq $ControlHost) {
            $evidence += "packet $($f.Name): $ControlHost with source http-host"
        }
    }
}
foreach ($f in @(Get-ChildItem (Join-Path $stateRoot 'logs') -Filter 'conn-*.jsonl' -ErrorAction SilentlyContinue)) {
    foreach ($line in Get-Content $f.FullName) {
        if ($line.Contains($ControlHost) -and $line.Contains('http-host')) { $evidence += "conn-log: $line" }
    }
}

if ($evidence.Count) {
    Write-Host 'POSITIVE CONTROL PASSED - http-host attribution observed live:' -ForegroundColor Green
    $evidence | ForEach-Object { Write-Host "  $_" }
    exit 0
}
Write-Host 'POSITIVE CONTROL NOT PROVEN: pipeline ran, but no http-host evidence for the control host.' -ForegroundColor Yellow
Write-Host 'Possible causes: capture blind on the active adapter (VPN offload), control connection not sampled.'
Write-Host "Inspect $stateRoot (op-log, packets) before drawing conclusions."
exit 2
