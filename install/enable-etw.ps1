# enable-etw.ps1 - enables the DNS-Client operational ETW channel that
# dnsetw.psm1 reads (GOAL: events 3006/3008 for domain+PID attribution).
# OPERATOR-RUN ONLY, requires admin. 64 MB ring per GOAL.

#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [System.Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'must run elevated (admin) - wevtutil sl requires it'
}

wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864
Write-Host 'channel enabled. verify:'
wevtutil gl Microsoft-Windows-DNS-Client/Operational | Select-String 'enabled|maxSize'
