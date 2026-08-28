# check-reputation.ps1 — Tier-2 MCP tool backend. The ONLY place in the whole
# pipeline where AbuseIPDB/VirusTotal are called (GOAL: reputation only on the
# already-filtered residual). READ-ONLY except its own quota ledger.
# Guards here are defense-in-depth duplicates of Tier-1's exclusions and are
# NOT model-overridable: a refusal is a normal JSON answer, not an error.

#Requires -Version 7
param([Parameter(Mandatory)] [string]$Ip)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

$stateRoot = $env:NETWATCH_STATE
if (-not $stateRoot) { Out-Result @{ error = 'NETWATCH_STATE not set' } }

# --- parse + non-routable guard ---------------------------------------------
$addr = $null
if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { Out-Result @{ error = 'not an IP literal' } }
$refuse = $null
if ([System.Net.IPAddress]::IsLoopback($addr))        { $refuse = 'loopback' }
elseif ($addr.IsIPv6LinkLocal)                        { $refuse = 'link-local' }
# TODO: RFC1918 (10/8, 172.16/12, 192.168/16), 169.254/16, multicast/reserved,
#       100.64.0.0/10 (Tailscale CGNAT) — implement CIDR checks here.

# --- own-IP guard (never send own public IP to reputation services) ----------
$ownFile = Join-Path $stateRoot 'state\ownip.json'
$own = (Test-Path $ownFile) ? (Get-Content $ownFile -Raw | ConvertFrom-Json) : $null
# ownip.json: { detected: [...], last_known: [...], recorded_static: [...] }
$ownAll = @($own?.detected) + @($own?.last_known) + @($own?.recorded_static) | Where-Object { $_ }
if ($Ip -in $ownAll) { $refuse = 'own public ip' }

if ($refuse) { Out-Result @{ refused = $refuse } }     # final; not overridable

# --- quota ledger (VT free tier ~500/day, 4/min; keep headroom) --------------
$ledgerFile = Join-Path $stateRoot 'state\repquota.json'
# TODO state ledger: { date, vt_today, vt_minute_window[], abuse_today }
#   if vt_today >= cfg.reputation_quota.vt_per_day -> vt lookup skipped
#   if minute window full -> wait-or-skip (never sleep past tool timeout 20s)
$quotaExhausted = $false # TODO
if ($quotaExhausted) { Out-Result @{ quota_exhausted = $true } }

# --- lookups (keys from env, injected by Tier 1 from DPAPI store) ------------
$abuseKey = $env:ABUSEIPDB_KEY
$vtKey    = $env:VT_KEY
$result = @{ ip = $Ip; abuseipdb = $null; virustotal = $null; quota = $null }
try {
    if ($abuseKey) {
        # GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90
        #   headers: Key, Accept: application/json
        # -> { score, total_reports, last_reported_at }   # TODO Invoke-RestMethod
    }
    if ($vtKey) {
        # GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
        #   header: x-apikey
        # -> last_analysis_stats { malicious, suspicious, harmless }   # TODO
    }
}
catch {
    # F12: unreachable/invalid key -> informative, never blocking
    Out-Result @{ ip = $Ip; error = 'lookup_unavailable'; detail = $_.Exception.Message }
}
# TODO: increment ledger AFTER successful calls, write back atomically.
Out-Result $result
