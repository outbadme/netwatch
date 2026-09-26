# bootstrap.tests.ps1 - src/tier1/start-netwatch.ps1 (the task's launcher):
# a too-old pwsh leaves bootstrap.log + exit 2 instead of a silent #Requires
# failure; otherwise arguments and exit code pass through to netwatch.ps1.
. "$PSScriptRoot\_assert.ps1"

$launcher = Join-Path $PSScriptRoot '..\src\tier1\start-netwatch.ps1'
$netwatch = Join-Path $PSScriptRoot '..\src\tier1\netwatch.ps1'
$pwshExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) "nw-boot-$PID"
$null = New-Item -ItemType Directory -Force -Path $tmp
$savedLad = $env:LOCALAPPDATA
try {
    # version gate (min raised above the running pwsh via the test seam)
    $env:LOCALAPPDATA = $tmp
    $env:NETWATCH_BOOTSTRAP_MIN = '99.0'
    $null = & $pwshExe -NoProfile -File $launcher 2>&1
    $rc = $LASTEXITCODE
    Remove-Item Env:NETWATCH_BOOTSTRAP_MIN
    $env:LOCALAPPDATA = $savedLad
    Assert-Equal 2 $rc 'too-old pwsh -> exit 2'
    $log = [IO.Path]::Combine($tmp, 'netwatch', 'logs', 'bootstrap.log')
    Assert-True (Test-Path -LiteralPath $log) 'bootstrap.log written'
    Assert-True ((Get-Content -LiteralPath $log -Raw) -match 'ERROR netwatch not started: PowerShell .* older than 99\.0') 'log names the version problem'

    # pass-through: same exit code as calling netwatch.ps1 directly
    $bad = Join-Path $tmp 'no-such-config.json'
    $null = & $pwshExe -NoProfile -File $netwatch -ConfigPath $bad -NoMutex -Once 2>&1
    $direct = $LASTEXITCODE
    $null = & $pwshExe -NoProfile -File $launcher -ConfigPath $bad -NoMutex -Once 2>&1
    Assert-Equal $direct $LASTEXITCODE "launcher passes args + exit code through (rc $direct)"
    Assert-True ($direct -ne 0) 'precondition: missing config is a failure'
}
finally {
    $env:LOCALAPPDATA = $savedLad
    Remove-Item Env:NETWATCH_BOOTSTRAP_MIN -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
Complete-Tests
