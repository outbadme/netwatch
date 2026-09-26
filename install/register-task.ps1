# register-task.ps1 - registers the Tier-1 logon scheduled task (DECISIONS D8:
# interactive user session - toasts + visible Tier-3 windows need it; highest
# available privileges for ETW read + packet capture).
# OPERATOR-RUN ONLY (machine change). Not executed by the implementer.

#Requires -Version 7.6
param(
    [string]$TaskName = 'netwatch-tier1'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# the #Requires-free launcher: an outdated pwsh is reported (bootstrap.log +
# toast) instead of the task failing silently on netwatch.ps1's #Requires
$entry = Join-Path $repoRoot 'src\tier1\start-netwatch.ps1'
$pwshExe = (Get-Command pwsh).Source

$action = New-ScheduledTaskAction -Execute $pwshExe `
    -Argument "-NoProfile -WindowStyle Hidden -File `"$entry`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
    -LogonType Interactive -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force
Write-Host "task '$TaskName' registered: logon trigger, interactive, highest available"
Write-Host 'start now with: Start-ScheduledTask -TaskName netwatch-tier1'
