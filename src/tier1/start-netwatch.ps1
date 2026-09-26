# start-netwatch.ps1 - what the logon task runs (install/register-task.ps1).
# Deliberately NO '#Requires': netwatch.ps1 needs pwsh 7.6, and a #Requires
# failure inside a hidden scheduled task is invisible - the monitor simply
# never starts. This launcher parses on any PowerShell (syntax kept 5.1-safe),
# checks the version itself, and on a mismatch leaves a trace the operator
# will see: a line in %LOCALAPPDATA%\netwatch\logs\bootstrap.log and, when
# BurntToast loads, a toast. Then it exits 2 (task history shows it too).
# All arguments are passed through to netwatch.ps1.

$min = [version]'7.6'
if ($env:NETWATCH_BOOTSTRAP_MIN) { $min = [version]$env:NETWATCH_BOOTSTRAP_MIN }   # test seam
$have = $PSVersionTable.PSVersion
$haveV = [version]::new($have.Major, $have.Minor)
if ($haveV -lt $min) {
    $msg = "netwatch not started: PowerShell $have is older than $min (running $((Get-Process -Id $PID).Path)). Upgrade: winget upgrade Microsoft.PowerShell"
    try {
        $logDir = Join-Path ([Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%')) 'netwatch\logs'
        if (-not (Test-Path -LiteralPath $logDir)) { $null = New-Item -ItemType Directory -Force -Path $logDir }
        Add-Content -LiteralPath (Join-Path $logDir 'bootstrap.log') -Value ('{0} ERROR {1}' -f [datetime]::UtcNow.ToString('o'), $msg)
    }
    catch {}
    if (-not $env:NETWATCH_SUPPRESS_TOAST) {
        try {
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text 'netwatch is NOT running', $msg
        }
        catch {}
    }
    Write-Error $msg
    exit 2
}

& (Join-Path $PSScriptRoot 'netwatch.ps1') @args
exit $LASTEXITCODE
