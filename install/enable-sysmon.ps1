# enable-sysmon.ps1 - installs Sysmon (or updates its config) with
# config/sysmon-netwatch.xml so sysmon.psm1 can read NetworkConnect (event 3)
# and see connections that open and close between two 30-s polls.
# OPERATOR-RUN ONLY, requires admin. Optional: without Sysmon netwatch keeps
# working on polling alone (health flag sysmon=unavailable in every packet).
#
# Sysmon is not redistributed here: download it from Sysinternals
# (https://learn.microsoft.com/sysinternals/downloads/sysmon), verify the
# signature, and pass the path, or have Sysmon64.exe on PATH.
#
# Already running Sysmon with your own config? Use -KeepExistingConfig: the
# script then only checks that the channel is enabled and sized.
#
# Non-elevated netwatch task: the Sysmon channel is readable by
# Administrators and, by default, the "Event Log Readers" group. If the
# task runs non-elevated and Test-SysmonAvailable reports 'unavailable',
# add that user to Event Log Readers (then sign out/in).

#Requires -Version 7
param(
    [string]$SysmonExe,
    [switch]$KeepExistingConfig
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'must run elevated (admin) - Sysmon install/config requires it'
}

$cfgFile = Join-Path $PSScriptRoot '..\config\sysmon-netwatch.xml' | Resolve-Path
$svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $KeepExistingConfig) {
    if (-not $SysmonExe) {
        $SysmonExe = (Get-Command 'Sysmon64.exe', 'Sysmon.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)?.Source
    }
    if (-not $SysmonExe -or -not (Test-Path -LiteralPath $SysmonExe)) {
        throw 'Sysmon executable not found - pass -SysmonExe <path to Sysmon64.exe> (download from Sysinternals)'
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $SysmonExe
    if ("$($sig.Status)" -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "refusing to run $SysmonExe - Authenticode status '$($sig.Status)', signer '$($sig.SignerCertificate.Subject)'"
    }
    if ($svc) {
        Write-Host "Sysmon service '$($svc.Name)' present - applying netwatch config"
        & $SysmonExe -c $cfgFile
    }
    else {
        Write-Host 'installing Sysmon with the netwatch config'
        & $SysmonExe -accepteula -i $cfgFile
    }
    if ($LASTEXITCODE -ne 0) { throw "Sysmon exited $LASTEXITCODE" }
}
elseif (-not $svc) {
    throw '-KeepExistingConfig given but no Sysmon service is installed'
}

# 64 MB ring, same as the DNS-Client channel. netwatch drains it every tick
# via its bookmark, so the ring only has to cover a stopped/restarting task.
wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true /ms:67108864
Write-Host 'Sysmon channel enabled. verify:'
wevtutil gl Microsoft-Windows-Sysmon/Operational | Select-String 'enabled|maxSize'
