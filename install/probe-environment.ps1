# probe-environment.ps1 — read-only environment probe for netwatch deploy.
# Reports presence/versions of every external dependency the pipeline needs.
# Safe to run as normal user; changes nothing.
# Jail rule: no literal outside-repo paths here — PATH lookup / env refs only.
#
# -Strict: exit 1 when anything is below its minimum or missing (CI, deploy
# gates); -AllowMissing <names> tolerates those components being ABSENT
# (never too old). Without -Strict the report is informational (exit 0).
#
# #Requires is 7.0 on purpose (the rest of netwatch needs 7.6): this probe
# must still run on an outdated pwsh to REPORT it as outdated.

#Requires -Version 7.0
param(
    [switch]$Strict,
    [string[]]$AllowMissing = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
# 'pwsh -File' passes 'a,b' as ONE string: accept comma lists
$AllowMissing = @($AllowMissing | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$result = [ordered]@{}

$result.pwsh_version = (Get-Host).Version.ToString()
$result.pwsh_path    = (Get-Command pwsh).Source

$node = Get-Command node -ErrorAction SilentlyContinue
$result.node_path    = $node ? $node.Source : $null
$result.node_version = $node ? (& node --version) : $null

$claude = Get-Command claude -ErrorAction SilentlyContinue
$result.claude_path    = $claude ? $claude.Source : $null
$result.claude_version = $claude ? ((& claude --version) -join ' ') : $null

$tsharkExe = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
$result.tshark_exists = Test-Path -LiteralPath $tsharkExe

$bt = Get-Module -ListAvailable BurntToast | Sort-Object Version -Descending | Select-Object -First 1
$result.burnttoast_version = $bt ? $bt.Version.ToString() : $null

try {
    $ev = Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents 1 -ErrorAction Stop
    $result.dns_etw = 'readable (last event id ' + $ev.Id + ')'
}
catch {
    $result.dns_etw = 'FAIL: ' + $_.Exception.Message
}

# MCP server dependencies (npm ci in src/tier2/mcp-server): Tier 2 has no
# tools without them
$mcpDir = Join-Path $PSScriptRoot '..\src\tier2\mcp-server'
if (-not (Test-Path -LiteralPath (Join-Path $mcpDir 'node_modules'))) { $result.mcp_deps = 'missing' }
elseif (-not (Get-Command npm -ErrorAction SilentlyContinue)) { $result.mcp_deps = 'unchecked (npm not on PATH)' }
else {
    $null = & npm ls --prefix $mcpDir --omit=dev 2>&1
    $result.mcp_deps = if ($LASTEXITCODE -eq 0) { 'ok' } else { "npm ls exit $LASTEXITCODE (missing/invalid packages)" }
}

# Sysmon is optional; when installed it must be new enough for the netwatch
# config (config/sysmon-netwatch.xml)
$result.sysmon_version = $null
if ($IsWindows) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($svc -and $svc.PathName) {
        $exe = $svc.PathName.Trim('"')
        try { $result.sysmon_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion } catch {}
    }
}

try {
    $result.tcp_sample_count = @(Get-NetTCPConnection -State Established -ErrorAction Stop).Count
}
catch {
    $result.tcp_sample_count = 'FAIL: ' + $_.Exception.Message
}

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
$result.is_admin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# documented minimums (README "Requirements", raised to current releases
# 2026-09-26: pwsh 7.6, Node 24 LTS, Claude CLI 2.1.283): anything below is reported,
# not fixed - installing/upgrading stays an operator action
function ConvertTo-Ver([string]$s) {
    if ($s -match '(\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] } else { return $null }
}
$min = [ordered]@{ pwsh = '7.6'; node = '24.0'; claude = '2.1.283'; burnttoast = '1.1.0'; sysmon = '15.0' }
$have = @{
    pwsh = ConvertTo-Ver $result.pwsh_version; node = ConvertTo-Ver $result.node_version
    claude = ConvertTo-Ver $result.claude_version; burnttoast = ConvertTo-Ver $result.burnttoast_version
    sysmon = ConvertTo-Ver $result.sysmon_version
}
$optional = @('sysmon')                       # absent is fine, too old is not
$result.below_minimum = @(foreach ($k in $min.Keys) {
        if ($null -eq $have[$k]) {
            if ($k -notin $optional -and $k -notin $AllowMissing) { "${k}: missing (min $($min[$k]))" }
        }
        elseif ($have[$k] -lt [version]$min[$k]) { "${k}: $($have[$k]) < $($min[$k])" }
    }
    if ($result.mcp_deps -ne 'ok' -and 'mcp_deps' -notin $AllowMissing) { "mcp_deps: $($result.mcp_deps)" })

[pscustomobject]$result | ConvertTo-Json
if ($Strict -and $result.below_minimum.Count) {
    Write-Host "probe: below minimum / missing: $($result.below_minimum -join '; ')" -ForegroundColor Red
    exit 1
}
exit 0
