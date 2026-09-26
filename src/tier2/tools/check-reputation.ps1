# check-reputation.ps1 - Tier-2 MCP tool backend. The ONLY place in the whole
# pipeline where AbuseIPDB/VirusTotal are called (GOAL: reputation only on the
# already-filtered residual). READ-ONLY except its own quota ledger.
# Guards here are defense-in-depth DUPLICATES of Tier-1's exclusions (no module
# import on purpose - this file must stay independently reviewable) and are
# NOT model-overridable: a refusal is a normal JSON answer, not an error.
# Env: NETWATCH_STATE (state root), ABUSEIPDB_KEY / VT_KEY (optional),
#      NETWATCH_VT_PER_DAY / NETWATCH_VT_PER_MIN / NETWATCH_ABUSE_PER_DAY
#      (optional quota overrides; defaults 400 / 4 / 900),
#      NETWATCH_LEDGER_WAIT_MS (ledger lock wait, default 5000; test seam).

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
# Canonicalize BEFORE any guard: TryParse accepts '3405803786', '10.1',
# '::ffff:10.0.0.1' and '2001:db8::1%junk&x=y' - raw-string own-IP matching
# and the raw string in the lookup URL were both bypassable (review finding).
# From here on $Ip is the canonical form and the only form ever used.
if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() } else { $addr.ScopeId = 0 }
}
$Ip = $addr.ToString()

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

function Get-RefuseReason([System.Net.IPAddress]$A) {
    if ([System.Net.IPAddress]::IsLoopback($A)) { return 'loopback' }
    if ($A.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($A.IsIPv6LinkLocal)                   { return 'link-local' }
        if ($A.IsIPv6Multicast)                   { return 'multicast' }
        if (Test-InCidr $A 'fc00::/7')            { return 'ula' }
        if ($A.Equals([System.Net.IPAddress]::IPv6Any)) { return 'reserved' }
        if (Test-InCidr $A '2001::/32')           { return 'tunnel' }   # Teredo embeds client IPv4
        return $null
    }
    if (Test-InCidr $A '169.254.0.0/16')          { return 'link-local' }
    if (Test-InCidr $A '10.0.0.0/8')              { return 'rfc1918' }
    if (Test-InCidr $A '172.16.0.0/12')           { return 'rfc1918' }
    if (Test-InCidr $A '192.168.0.0/16')          { return 'rfc1918' }
    if (Test-InCidr $A '100.64.0.0/10')           { return 'cgnat' }
    if (Test-InCidr $A '224.0.0.0/4')             { return 'multicast' }
    if (Test-InCidr $A '0.0.0.0/8')               { return 'reserved' }
    if (Test-InCidr $A '240.0.0.0/4')             { return 'reserved' }
    return $null
}

# IPv4 carried inside an IPv6 transition address (NAT64 64:ff9b::/96,
# IPv4-compatible ::/96, 6to4 2002::/16) is judged like the address itself:
# 64:ff9b::<own ip> must not leak the own IP.
$embedded = $null
if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    $b = $addr.GetAddressBytes()
    $off = -1
    if ((Test-InCidr $addr '64:ff9b::/96') -or (Test-InCidr $addr '::/96')) { $off = 12 }
    elseif (Test-InCidr $addr '2002::/16') { $off = 2 }
    if ($off -ge 0) { $embedded = [System.Net.IPAddress]::new([byte[]]$b[$off..($off + 3)]) }
}

$refuse = Get-RefuseReason $addr
if (-not $refuse -and $embedded) { $refuse = Get-RefuseReason $embedded }
$candidates = @($Ip) + @(if ($embedded) { $embedded.ToString() })

# --- own-IP guard (never send own public IP to reputation services) ----------
# The recorded static value is HARDCODED here on purpose (TIER2-CONTRACT 1.3):
# this guard must hold even with a missing/foreign NETWATCH_STATE.
if (-not $refuse -and '203.0.113.10' -in $candidates) { $refuse = 'own public ip' }
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
            $ownCanon = foreach ($o in @($ownAll | Where-Object { $_ })) {
                $oa = $null
                if ([System.Net.IPAddress]::TryParse([string]$o, [ref]$oa)) {
                    if ($oa.IsIPv4MappedToIPv6) { $oa = $oa.MapToIPv4() }
                    elseif ($oa.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $oa.ScopeId = 0 }
                    $oa.ToString()
                }
            }
            if (@($candidates | Where-Object { $_ -in @($ownCanon) }).Count) { $refuse = 'own public ip' }
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

# The model may call this tool in parallel; an unlocked read-check-write let
# concurrent calls all pass the 4/min check (review finding). Quota is now
# RESERVED under a named mutex before the lookup and refunded if the lookup
# fails - "spent only on success" still holds, and no two calls can claim the
# same slot. The mutex name is derived from the ledger path so separate state
# roots (tests) never contend with the live one.
$mutexName = 'netwatch-repquota-' + [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($ledgerFile.ToLowerInvariant()))).Substring(0, 16)
$ledgerMutex = [System.Threading.Mutex]::new($false, $mutexName)
# Time budget vs the MCP server's 20 s per-call kill: pwsh startup (~1-3 s)
# + reserve wait (<= 1 s) + 2 lookups (6 s each) + refund wait (<= 1 s)
# stays under 20 s. A kill after the reserve would leak the reservation.
$lockWaitMs = if ($env:NETWATCH_LEDGER_WAIT_MS) { [int]$env:NETWATCH_LEDGER_WAIT_MS } else { 1000 }

function Invoke-LedgerLocked([scriptblock]$Body, [switch]$BestEffort) {
    # Default: a busy ledger fails closed BEFORE any lookup (nothing spent).
    # -BestEffort (post-lookup refund): a busy ledger returns $null instead -
    # results already fetched must never be discarded over bookkeeping.
    $held = $false
    try { $held = $ledgerMutex.WaitOne($lockWaitMs) }
    catch [System.Threading.AbandonedMutexException] { $held = $true }   # previous holder was killed
    if (-not $held) {
        if ($BestEffort) { return $null }
        Out-Result @{ error = 'quota ledger busy'; abuseipdb_note = 'lookup_unavailable'; virustotal_note = 'lookup_unavailable' }
    }
    try { return & $Body }
    finally { $ledgerMutex.ReleaseMutex() }
}

# vt_minute stamps are written in a compact form ConvertFrom-Json does NOT
# auto-convert to DateTime, so the refund can match its own stamp as an exact
# string. Older ledgers hold ISO 'o' stamps, which ConvertFrom-Json turns
# into DateTime objects - both forms are read.
$stampFormat = 'yyyyMMdd\THHmmssfffffff\Z'
function Get-StampUtc($V) {
    if ($V -is [datetime]) { return $V.ToUniversalTime() }
    $d = [datetime]::MinValue
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sty = [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal'
    if ([datetime]::TryParseExact([string]$V, $stampFormat, $inv, $sty, [ref]$d)) { return $d }
    if ([datetime]::TryParse([string]$V, $inv, $sty, [ref]$d)) { return $d }
    return $null
}

function Read-Ledger {
    $l = $null
    if (Test-Path -LiteralPath $ledgerFile) {
        try { $l = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json } catch {}
    }
    $today = Get-Date -Format 'yyyy-MM-dd'
    if (-not $l -or $l.date -ne $today) {
        $l = [pscustomobject]@{ date = $today; vt_today = 0; vt_minute = @(); abuse_today = 0 }
    }
    $cut = [datetime]::UtcNow.AddSeconds(-60)
    $l.vt_minute = @(@($l.vt_minute) | Where-Object { $_ -and ($t = Get-StampUtc $_) -and $t -gt $cut })
    return $l
}

function Write-Ledger($L) {
    $L | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ledgerFile -Encoding utf8
}

# --- reserve (keys from env, injected by Tier 1 from DPAPI store) ------------
$abuseKey = $env:ABUSEIPDB_KEY
$vtKey    = $env:VT_KEY
$grant = Invoke-LedgerLocked {
    $l = Read-Ledger
    # stamp taken INSIDE the lock, right before the lookup: a stamp taken
    # before the lock wait would age the 60 s window early and let a 5th
    # call in within one real minute (review finding)
    $script:stamp = [datetime]::UtcNow.ToString($stampFormat, [Globalization.CultureInfo]::InvariantCulture)
    $vtAllowed = ($l.vt_today -lt $vtPerDay) -and (@($l.vt_minute).Count -lt $vtPerMin)
    $abAllowed = ($l.abuse_today -lt $abPerDay)
    $g = @{ vtAllowed = $vtAllowed; abAllowed = $abAllowed; vt = $false; ab = $false }
    if ($vtKey -and $vtAllowed) {
        $l.vt_today++
        $l.vt_minute = @($l.vt_minute) + @($stamp)
        $g.vt = $true
    }
    if ($abuseKey -and $abAllowed) { $l.abuse_today++; $g.ab = $true }
    if ($g.vt -or $g.ab) { Write-Ledger $l }
    $g.vt_today = $l.vt_today; $g.abuse_today = $l.abuse_today   # snapshot for the report
    $g.date = $l.date                                            # refund applies to THIS day only
    $g
}
if (-not $grant.vtAllowed -and -not $grant.abAllowed) { Out-Result @{ quota_exhausted = $true } }

# --- lookups ------------------------------------------------------------------
$result = [ordered]@{ ip = $Ip; abuseipdb = $null; virustotal = $null; quota = $null }
$spentVt = $false; $spentAb = $false
# Per-service try/catch (F12): one failing service must not erase the other's
# answer nor lose its ledger accounting. TimeoutSec 6 keeps the worst case
# (2 lookups + pwsh startup) inside the MCP server's 20 s per-call cap.
if ($grant.ab) {
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

if ($grant.vt) {
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

# refund reservations whose lookup failed (quota is spent on success only)
$refundVt = $grant.vt -and -not $spentVt
$refundAb = $grant.ab -and -not $spentAb
$counts = @{ vt_today = $grant.vt_today; abuse_today = $grant.abuse_today }
if ($refundVt -or $refundAb) {
    # lock taken ONLY when there is something to give back; a busy ledger
    # skips the refund (over-counts by one, never over-spends) and keeps the
    # already-fetched answers
    $refunded = Invoke-LedgerLocked -BestEffort {
        $l = Read-Ledger
        # reserved before midnight, refunding after: the reservation lived in
        # yesterday's counters, which are gone - decrementing today's would
        # steal another call's reservation (review finding)
        if ($l.date -ne $grant.date) {
            return @{ vt_today = $l.vt_today; abuse_today = $l.abuse_today }
        }
        if ($refundVt) {
            $l.vt_today = [math]::Max(0, $l.vt_today - 1)
            $l.vt_minute = @(@($l.vt_minute) | Where-Object { -not ($_ -is [string] -and $_ -eq $stamp) })
        }
        if ($refundAb) { $l.abuse_today = [math]::Max(0, $l.abuse_today - 1) }
        Write-Ledger $l
        @{ vt_today = $l.vt_today; abuse_today = $l.abuse_today }
    }
    if ($refunded) { $counts = $refunded }
    else { $result['quota_note'] = 'refund_skipped_ledger_busy' }
}
$result.quota = @{
    vt_remaining_today    = [math]::Max(0, $vtPerDay - $counts.vt_today)
    abuse_remaining_today = [math]::Max(0, $abPerDay - $counts.abuse_today)
}
Out-Result $result
