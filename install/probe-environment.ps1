# probe-environment.ps1 — read-only environment probe for netwatch deploy.
# Reports presence/versions of every external dependency the pipeline needs.
# Safe to run as normal user; changes nothing.
# Jail rule: no literal outside-repo paths here — PATH lookup / env refs only.

#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

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

try {
    $result.tcp_sample_count = @(Get-NetTCPConnection -State Established -ErrorAction Stop).Count
}
catch {
    $result.tcp_sample_count = 'FAIL: ' + $_.Exception.Message
}

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
$result.is_admin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# documented minimums (README "Requirements"): anything below is reported,
# not fixed - installing/upgrading stays an operator action
function ConvertTo-Ver([string]$s) {
    if ($s -match '(\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] } else { return $null }
}
$min = [ordered]@{ pwsh = '7.4'; node = '22.0'; claude = '2.1.223'; burnttoast = '1.1.0' }
$have = @{
    pwsh = ConvertTo-Ver $result.pwsh_version; node = ConvertTo-Ver $result.node_version
    claude = ConvertTo-Ver $result.claude_version; burnttoast = ConvertTo-Ver $result.burnttoast_version
}
$result.below_minimum = @(foreach ($k in $min.Keys) {
        if ($null -eq $have[$k]) { "${k}: missing (min $($min[$k]))" }
        elseif ($have[$k] -lt [version]$min[$k]) { "${k}: $($have[$k]) < $($min[$k])" }
    })

[pscustomobject]$result | ConvertTo-Json
