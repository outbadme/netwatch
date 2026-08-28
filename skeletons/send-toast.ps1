# send-toast.ps1 — toast wrapper (DECISIONS.md D4: BurntToast >= 1.1.0,
# New-BurntToastNotification only; failure never blocks the pipeline, F16).
# Usage: pwsh -File send-toast.ps1 -Title 'netwatch' -Message '...' [-Urgent]

#Requires -Version 7
param(
    [Parameter(Mandatory)] [string]$Title,
    [Parameter(Mandatory)] [string]$Message,
    [switch]$Urgent
)
try {
    Import-Module BurntToast -ErrorAction Stop
    $args = @{ Text = @($Title, $Message) }
    # BurntToast 1.1.0: -Urgent maps to Important Notifications; verify the
    # exact parameter name against the installed module at deploy time.
    if ($Urgent) { $args['Urgent'] = $true }
    New-BurntToastNotification @args
    exit 0
}
catch {
    # F16: log and continue — the ALARM surface is the Tier-3 window, not the toast.
    Write-Error "toast failed: $($_.Exception.Message)"
    exit 1
}
