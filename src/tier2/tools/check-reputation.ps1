# check-reputation.ps1 - Tier-2 MCP tool backend. The ONLY place in the whole
# pipeline where AbuseIPDB/VirusTotal are called (GOAL: reputation only on the
# already-filtered residual). READ-ONLY except its own quota ledger.
# Guards here are defense-in-depth DUPLICATES of Tier-1's exclusions (no module
# import on purpose - this file must stay independently reviewable) and are
# NOT model-overridable: a refusal is a normal JSON answer, not an error.
# Env: NETWATCH_STATE (state root), ABUSEIPDB_KEY / VT_KEY (optional),
#      NETWATCH_VT_PER_DAY / NETWATCH_VT_PER_MIN / NETWATCH_ABUSE_PER_DAY
#      (optional quota overrides; defaults 400 / 4 / 900).

#Requires -Version 7
param([Parameter(Mandatory)] [string]$Ip)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

$stateRoot = $env:NETWATCH_STATE
if (-not $stateRoot) { Out-Result @{ error = 'NETWATCH_STATE not set' } }

# --- parse + non-routable guard (minimal standalone CIDR math) ---------------
$addr = $null
if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { Out-Result @{ error = 'not an IP literal' } }

function Test-InCidr([System.Net.IPAddress]$A, [string]$Cidr) {
    $parts = $Cidr.Split('/')
    $base = [System.Net.IPAddress]::Parse($parts[0])
    $prefix = [int]$parts[1]
    if ($A.AddressFamily -ne $base.AddressFamily) { return $false }
    $ab = $A.GetAddressBytes(); $bb = $base.GetAddressBytes()
    $full = [math]::Floor($prefix / 8)
    for ($i = 0; $i -lt $full; $i++) { if ($ab[$i] -ne $bb[$i]) { return $false } }
    $rem = $prefix % 8
    if ($rem -gt 0) {
        $mask = (0xFF -shl (8 - $rem)) -band 0xFF
        if (($ab[$full] -band $mask) -ne ($bb[$full] -band $mask)) { return $false }
    }
    return $true
}

$refuse = $null
if ([System.Net.IPAddress]::IsLoopback($addr)) { $refuse = 'loopback' }
elseif ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if     ($addr.IsIPv6LinkLocal)                { $refuse = 'link-local' }
    elseif ($addr.IsIPv6Multicast)                { $refuse = 'multicast' }
    elseif (Test-InCidr $addr 'fc00::/7')         { $refuse = 'ula' }
}
else {
    if     (Test-InCidr $addr '169.254.0.0/16')   { $refuse = 'link-local' }
    elseif (Test-InCidr $addr '10.0.0.0/8')       { $refuse = 'rfc1918' }
    elseif (Test-InCidr $addr '172.16.0.0/12')    { $refuse = 'rfc1918' }
    elseif (Test-InCidr $addr '192.168.0.0/16')   { $refuse = 'rfc1918' }
    elseif (Test-InCidr $addr '100.64.0.0/10')    { $refuse = 'cgnat' }
    elseif (Test-InCidr $addr '224.0.0.0/4')      { $refuse = 'multicast' }
    elseif (Test-InCidr $addr '0.0.0.0/8')        { $refuse = 'reserved' }
    elseif (Test-InCidr $addr '240.0.0.0/4')      { $refuse = 'reserved' }
}

# --- own-IP guard (never send own public IP to reputation services) ----------
# The recorded static value is HARDCODED here on purpose (TIER2-CONTRACT 1.3):
# this guard must hold even with a missing/foreign NETWATCH_STATE.
if (-not $refuse -and $Ip -eq '203.0.113.10') { $refuse = 'own public ip' }
if (-not $refuse) {
    $ownFile = Join-Path $stateRoot 'state\ownip.json'
    if (-not (Test-Path -LiteralPath $ownFile)) {
        # fail closed: without the state we cannot prove this is not our IP
        $refuse = 'own-ip state unavailable (fail closed)'
    }
    else {
        try {
            $own = Get-Content -LiteralPath $ownFile -Raw | ConvertFrom-Json
            $ownAll = @()
            foreach ($f in 'detected', 'last_known', 'recorded_static') {
                if ($own.PSObject.Properties[$f]) { $ownAll += @($own.$f) }
            }
            if ($own.PSObject.Properties['previous']) {
                $ownAll += @($own.previous | ForEach-Object ip)
            }
            if ($Ip -in ($ownAll | Where-Object { $_ })) { $refuse = 'own public ip' }
        }
        catch { $refuse = 'own-ip state unreadable (fail closed)' }
    }
}

if ($refuse) { Out-Result @{ refused = $refuse } }     # final; not overridable

# --- quota ledger (VT free tier ~500/day, 4/min; keep headroom) --------------
$vtPerDay  = if ($env:NETWATCH_VT_PER_DAY)    { [int]$env:NETWATCH_VT_PER_DAY }    else { 400 }
$vtPerMin  = if ($env:NETWATCH_VT_PER_MIN)    { [int]$env:NETWATCH_VT_PER_MIN }    else { 4 }
$abPerDay  = if ($env:NETWATCH_ABUSE_PER_DAY) { [int]$env:NETWATCH_ABUSE_PER_DAY } else { 900 }

$ledgerFile = Join-Path $stateRoot 'state\repquota.json'
$today = Get-Date -Format 'yyyy-MM-dd'
$ledger = $null
if (Test-Path -LiteralPath $ledgerFile) {
    try { $ledger = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json } catch {}
}
if (-not $ledger -or $ledger.date -ne $today) {
    $ledger = [pscustomobject]@{ date = $today; vt_today = 0; vt_minute = @(); abuse_today = 0 }
}
$nowUtc = [datetime]::UtcNow
$minuteWindow = @(@($ledger.vt_minute) | Where-Object {
        $_ -and ([datetime]::Parse($_).ToUniversalTime() -gt $nowUtc.AddSeconds(-60)) })

$vtAllowed = ($ledger.vt_today -lt $vtPerDay) -and ($minuteWindow.Count -lt $vtPerMin)
$abAllowed = ($ledger.abuse_today -lt $abPerDay)
if (-not $vtAllowed -and -not $abAllowed) { Out-Result @{ quota_exhausted = $true } }

# --- lookups (keys from env, injected by Tier 1 from DPAPI store) ------------
$abuseKey = $env:ABUSEIPDB_KEY
$vtKey    = $env:VT_KEY
$result = [ordered]@{ ip = $Ip; abuseipdb = $null; virustotal = $null; quota = $null }
$spentVt = $false; $spentAb = $false
# Per-service try/catch (F12): one failing service must not erase the other's
# answer nor lose its ledger accounting. TimeoutSec 6 keeps the worst case
# (2 lookups + pwsh startup) inside the MCP server's 20 s per-call cap.
if ($abuseKey -and $abAllowed) {
    try {
        $r = Invoke-RestMethod -TimeoutSec 6 -Method Get `
            -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$Ip&maxAgeInDays=90" `
            -Headers @{ Key = $abuseKey; Accept = 'application/json' }
        $result.abuseipdb = @{
            score            = $r.data.abuseConfidenceScore
            total_reports    = $r.data.totalReports
            last_reported_at = $r.data.lastReportedAt
        }
        $spentAb = $true
    }
    catch { $result['abuseipdb_note'] = 'lookup_unavailable' }
}
elseif (-not $abuseKey) { $result['abuseipdb_note'] = 'no_key' }
else                    { $result['abuseipdb_note'] = 'quota_exhausted' }

if ($vtKey -and $vtAllowed) {
    try {
        $r = Invoke-RestMethod -TimeoutSec 6 -Method Get `
            -Uri "https://www.virustotal.com/api/v3/ip_addresses/$Ip" `
            -Headers @{ 'x-apikey' = $vtKey }
        $stats = $r.data.attributes.last_analysis_stats
        $result.virustotal = @{
            malicious  = $stats.malicious
            suspicious = $stats.suspicious
            harmless   = $stats.harmless
        }
        $spentVt = $true
    }
    catch { $result['virustotal_note'] = 'lookup_unavailable' }
}
elseif (-not $vtKey) { $result['virustotal_note'] = 'no_key' }
else                 { $result['virustotal_note'] = 'quota_exhausted' }

# increment ledger AFTER successful calls only
if ($spentVt) {
    $ledger.vt_today++
    $ledger.vt_minute = @($minuteWindow) + @($nowUtc.ToString('o'))
}
if ($spentAb) { $ledger.abuse_today++ }
if ($spentVt -or $spentAb) {
    $ledger | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ledgerFile -Encoding utf8
}
$result.quota = @{
    vt_remaining_today    = [math]::Max(0, $vtPerDay - $ledger.vt_today)
    abuse_remaining_today = [math]::Max(0, $abPerDay - $ledger.abuse_today)
}
Out-Result $result
