# enable-sysmon.ps1 - installs Sysmon (or updates its config) with
# config/sysmon-netwatch.xml so sysmon.psm1 can read NetworkConnect (event 3)
# and see connections that open and close between two 30-s polls.
# OPERATOR-RUN ONLY, requires admin. Optional: without Sysmon netwatch keeps
# working on polling alone (health flag sysmon=unavailable in every packet).
#
# Sysmon 15.0 or newer. It is not redistributed here: download it from
# Sysinternals (https://learn.microsoft.com/sysinternals/downloads/sysmon),
# and pass the path, or have Sysmon64.exe on PATH. The script refuses a
# binary that is not validly signed with O=Microsoft Corporation.
#
# Sysmon already installed? The script will not silently replace your
# config. Choose one:
#   -KeepExistingConfig     keep yours (it must log NetworkConnect for TCP);
#                           only the event channel is enabled/sized.
#   -ReplaceExistingConfig  apply the netwatch config. The current config is
#                           first saved to state\sysmon-backup-<time>\: the
#                           'Sysmon -c' dump (a readable record) and a
#                           registry export of the driver's rule set. The XML
#                           you originally applied is the real source for a
#                           restore ('Sysmon64 -c <your.xml>').
#
# Non-elevated netwatch task: the Sysmon channel is readable by
# Administrators and, by default, the "Event Log Readers" group. If the
# task runs non-elevated and Test-SysmonAvailable reports 'unavailable',
# add that user to Event Log Readers (then sign out/in).

#Requires -Version 7.6
param(
    [string]$SysmonExe,
    [switch]$KeepExistingConfig,
    [switch]$ReplaceExistingConfig,
    [string]$BackupRoot = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch\state')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'installutil.psm1') -Force

$minVersion = [version]'15.0'
if ($KeepExistingConfig -and $ReplaceExistingConfig) { throw 'choose one of -KeepExistingConfig / -ReplaceExistingConfig' }

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'must run elevated (admin) - Sysmon install/config requires it'
}

$cfgFile = Join-Path $PSScriptRoot '..\config\sysmon-netwatch.xml' | Resolve-Path
$svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1

if ($KeepExistingConfig) {
    if (-not $svc) { throw '-KeepExistingConfig given but no Sysmon service is installed' }
    $svcExe = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").PathName.Trim('"')
    $v = Get-FileVersionNumber -Path $svcExe
    if ($null -eq $v -or $v -lt $minVersion) { throw "installed Sysmon $v is older than $minVersion - upgrade it first" }
}
else {
    if ($svc -and -not $ReplaceExistingConfig) {
        throw "Sysmon service '$($svc.Name)' is already installed with a config. Pass -KeepExistingConfig (use yours; it must log TCP NetworkConnect) or -ReplaceExistingConfig (backs up the current config, then applies netwatch's)."
    }
    if (-not $SysmonExe) {
        $SysmonExe = (Get-Command 'Sysmon64.exe', 'Sysmon.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)?.Source
    }
    if (-not $SysmonExe -or -not (Test-Path -LiteralPath $SysmonExe)) {
        throw 'Sysmon executable not found - pass -SysmonExe <path to Sysmon64.exe> (download from Sysinternals)'
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $SysmonExe
    if ("$($sig.Status)" -ne 'Valid' -or -not $sig.SignerCertificate -or
        -not (Test-CertOrganization -Certificate $sig.SignerCertificate -Organization 'Microsoft Corporation')) {
        throw "refusing to run $SysmonExe - Authenticode status '$($sig.Status)', signer '$($sig.SignerCertificate?.Subject)'"
    }
    $v = Get-FileVersionNumber -Path $SysmonExe
    if ($null -eq $v -or $v -lt $minVersion) { throw "Sysmon $v at $SysmonExe is older than $minVersion - download the current release" }

    if ($svc) {
        $bk = Join-Path $BackupRoot ('sysmon-backup-' + [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
        $null = New-Item -ItemType Directory -Force -Path $bk
        & $SysmonExe -c | Set-Content -LiteralPath (Join-Path $bk 'sysmon-c-dump.txt') -Encoding utf8
        if ($LASTEXITCODE -ne 0) { throw "Sysmon -c (dump) exited $LASTEXITCODE - nothing changed" }
        $drv = @('SysmonDrv', 'SysmonDrv64') | Where-Object { Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_\Parameters" } | Select-Object -First 1
        if ($drv) {
            & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$drv\Parameters" (Join-Path $bk "$drv-Parameters.reg") /y | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "reg export exited $LASTEXITCODE - nothing changed" }
        }
        Write-Host "current Sysmon config saved to $bk - applying netwatch config"
        & $SysmonExe -c $cfgFile
    }
    else {
        Write-Host "installing Sysmon $v with the netwatch config"
        & $SysmonExe -accepteula -i $cfgFile
    }
    if ($LASTEXITCODE -ne 0) { throw "Sysmon exited $LASTEXITCODE" }
}

# at least 64 MB, same as the DNS-Client channel (a larger operator setting
# is kept). netwatch drains it every tick via its bookmark, so the ring only
# has to cover a stopped/restarting task.
$r = Enable-EventChannel -Channel 'Microsoft-Windows-Sysmon/Operational' -MinBytes 67108864
Write-Host "channel $($r.channel): enabled=$($r.enabled) maxSize=$($r.max_size)"
if (-not $r.enabled) { throw 'Sysmon channel still reports enabled=false' }
