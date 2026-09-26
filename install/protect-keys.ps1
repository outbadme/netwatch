# protect-keys.ps1 - converts a plaintext key file (KEY=VALUE lines, see
# .env.example: ABUSEIPDB_KEY, VT_KEY) into the DPAPI-protected
# state\apikeys.dat consumed by invoke-tier2.ps1. CurrentUser scope: only
# this Windows account can decrypt. Offers to delete the plaintext source.

#Requires -Version 7.6
param(
    [Parameter(Mandatory)] [string]$EnvFile,
    [string]$StateRoot = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch'),
    [switch]$DeleteSource
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $EnvFile)) { throw "key file not found: $EnvFile" }

$keys = @{ abuseipdb = $null; vt = $null }
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim()
    if (-not $t -or $t.StartsWith('#')) { continue }
    $eq = $t.IndexOf('=')
    if ($eq -lt 1) { continue }
    $name = $t.Substring(0, $eq).Trim()
    $value = $t.Substring($eq + 1).Trim()
    if (-not $value) { continue }
    switch ($name) {
        'ABUSEIPDB_KEY' { $keys.abuseipdb = $value }
        'VT_KEY'        { $keys.vt = $value }
    }
}
if (-not $keys.abuseipdb -and -not $keys.vt) {
    throw 'no ABUSEIPDB_KEY/VT_KEY values found - nothing to protect'
}

$null = New-Item -ItemType Directory -Force -Path (Join-Path $StateRoot 'state')
$plain = [Text.Encoding]::UTF8.GetBytes(($keys | ConvertTo-Json -Compress))
$enc = [System.Security.Cryptography.ProtectedData]::Protect(
    $plain, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$outFile = Join-Path $StateRoot 'state\apikeys.dat'
[IO.File]::WriteAllBytes($outFile, $enc)
Write-Host "protected keys written -> $outFile (abuseipdb=$([bool]$keys.abuseipdb), vt=$([bool]$keys.vt))"

if ($DeleteSource) {
    Remove-Item -LiteralPath $EnvFile -Force
    Write-Host "plaintext source deleted: $EnvFile"
}
else {
    Write-Host "REMINDER: delete the plaintext key file after verifying: $EnvFile"
}
