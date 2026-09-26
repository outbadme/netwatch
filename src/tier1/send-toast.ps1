# send-toast.ps1 - toast wrapper (DECISIONS D4: BurntToast >= 1.1.0,
# New-BurntToastNotification only; failure never blocks the pipeline, F16).
# Standalone script so tier3/launch-tier3.ps1 can call it via pwsh -File.
# Usage: pwsh -File send-toast.ps1 -Title 'netwatch' -Message '...' [-Urgent]
# Exit 0 = toast shown, 1 = toast failed (caller logs and continues).

#Requires -Version 7.4
param(
    [Parameter(Mandatory)] [string]$Title,
    [Parameter(Mandatory)] [string]$Message,
    [switch]$Urgent
)
# Test-suite gate: suppressed toasts report success without showing anything
# (set by tests/_assert.ps1; suite reruns must not flood the notification
# center with ALARM/CLEAN toasts - operator report 2026-08-27).
if ($env:NETWATCH_SUPPRESS_TOAST) { exit 0 }
try {
    Import-Module BurntToast -ErrorAction Stop
    $params = @{ Text = @($Title, $Message) }
    # BurntToast 1.1.0 exposes urgency via -Urgent (verify the exact parameter
    # name at deploy; guarded here so an older/newer module still toasts).
    if ($Urgent -and (Get-Command New-BurntToastNotification).Parameters.ContainsKey('Urgent')) {
        $params['Urgent'] = $true
    }
    New-BurntToastNotification @params
    exit 0
}
catch {
    # F16: the ALARM surface is the Tier-3 window, not the toast.
    Write-Error "toast failed: $($_.Exception.Message)"
    exit 1
}
