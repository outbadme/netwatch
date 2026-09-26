# enable-etw.ps1 - enables the DNS-Client operational ETW channel that
# dnsetw.psm1 reads (GOAL: events 3006/3008 for domain+PID attribution).
# OPERATOR-RUN ONLY, requires admin. Ring of at least 64 MB per GOAL; a
# larger size the operator already set is kept.

#Requires -Version 7.6
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'installutil.psm1') -Force

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'must run elevated (admin) - wevtutil sl requires it'
}

$r = Enable-EventChannel -Channel 'Microsoft-Windows-DNS-Client/Operational' -MinBytes 67108864
Write-Host "channel $($r.channel): enabled=$($r.enabled) maxSize=$($r.max_size)"
if (-not $r.enabled) { throw 'channel still reports enabled=false' }
