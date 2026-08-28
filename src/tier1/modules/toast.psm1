# toast.psm1 - in-process wrapper around send-toast.ps1 (F16: failures are
# logged, never thrown; a lost toast must not stop monitoring).

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'state.psm1')

function Send-NetwatchToast {
    # Returns $true when the toast was shown, $false otherwise.
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [string]$Message,
        [switch]$Urgent
    )
    try {
        $script = Join-Path $PSScriptRoot '..\send-toast.ps1'
        $toastArgs = @('-NoProfile', '-File', $script, '-Title', $Title, '-Message', $Message)
        if ($Urgent) { $toastArgs += '-Urgent' }
        & pwsh @toastArgs 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
        Write-OpLog -Config $Config -Level ERROR -Message "toast failed (exit $LASTEXITCODE): $Title"
        return $false
    }
    catch {
        Write-OpLog -Config $Config -Level ERROR -Message "toast failed: $($_.Exception.Message)"
        return $false
    }
}

Export-ModuleMember -Function Send-NetwatchToast
