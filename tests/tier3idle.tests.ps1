# tier3idle.tests.ps1 - task docs/plans/TIER3-IDLE-CLOSE-20260828.md:
# watchdog idle auto-close, operator-close path, report content, and the
# rightmost-screen top-right window placement.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier3\tier3win.psm1" -Force

$watchdog = "$PSScriptRoot\..\src\tier3\tier3-watchdog.ps1"
$root = New-TestStateRoot
$reportDir = Join-Path $root 'reports'
$null = New-Item -ItemType Directory -Force -Path $reportDir

function New-Sleeper {
    return Start-Process -FilePath (Get-Command pwsh).Source -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 600')
}
function Wait-Report {
    param([int]$TimeoutSec = 40)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $f = @(Get-ChildItem -LiteralPath $reportDir -Filter '*-tier3-*.md' -ErrorAction SilentlyContinue)
        if ($f.Count -gt 0) { return $f[0] }
        Start-Sleep -Seconds 1
    }
    return $null
}
function Start-Watchdog {
    param([int]$PidToWatch, [int]$ThresholdMs, [string]$Opened)
    return Start-Process -FilePath (Get-Command pwsh).Source -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-File', $watchdog,
            '-TargetPid', $PidToWatch, '-Keys', 'testproc|example.com|443',
            '-PacketPath', (Join-Path $root '20260828-000000-000-packet.json'),
            '-SessionId', 'test-session', '-OpenedUtc', $Opened,
            '-IdleThresholdMs', $ThresholdMs, '-ReportDir', $reportDir)
}

try {
    # --- 1. idle path: threshold exceeded -> tree killed + report ----------
    Set-Content -LiteralPath (Join-Path $root '20260828-000000-000-packet.json') -Value '{}' -Encoding ascii
    $env:NETWATCH_TEST_IDLE_MS = '999999999'
    $sleeper = New-Sleeper
    $wd = Start-Watchdog -PidToWatch $sleeper.Id -ThresholdMs 500 -Opened '2026-08-28T00:00:00Z'
    $rep = Wait-Report
    Assert-NotNull $rep 'idle path: report file appears'
    Assert-Null (Get-Process -Id $sleeper.Id -ErrorAction SilentlyContinue) 'idle path: window process tree killed'
    $txt = Get-Content -LiteralPath $rep.FullName -Raw
    Assert-True ($txt -match 'operator idle auto-close') 'idle path: close_reason recorded'
    Assert-True ($txt -match 'testproc\|example\.com\|443') 'idle path: keys recorded'
    Assert-True ($txt -match '20260828-000000-000-packet\.json') 'idle path: packet path recorded'
    Assert-True ($txt -match 'test-session') 'idle path: session id recorded'
    Assert-Null (Get-Process -Id $wd.Id -ErrorAction SilentlyContinue) 'idle path: watchdog exits after closing'
    Remove-Item -LiteralPath $rep.FullName -Force

    # --- 2. operator-close path: target dies on its own -> report ----------
    $env:NETWATCH_TEST_IDLE_MS = '0'
    $sleeper2 = New-Sleeper
    $wd2 = Start-Watchdog -PidToWatch $sleeper2.Id -ThresholdMs 500 -Opened '2026-08-28T00:00:00Z'
    Start-Sleep -Seconds 2
    Stop-Process -Id $sleeper2.Id -Force
    $rep2 = Wait-Report
    Assert-NotNull $rep2 'operator path: report file appears'
    Assert-True ((Get-Content -LiteralPath $rep2.FullName -Raw) -match 'closed by operator') 'operator path: close_reason recorded'
    Assert-Null (Get-Process -Id $wd2.Id -ErrorAction SilentlyContinue) 'operator path: watchdog exits'

    # --- 3. placement: a conhost-hosted payload moves its own window to ----
    # --- the rightmost screen's top-right corner (self-positioning) -------
    $scr = Get-RightmostScreen
    $rectFile = Join-Path $root 'rect.txt'
    $modPath = "$PSScriptRoot\..\src\tier3\tier3win.psm1"
    $body = @"
Import-Module '$modPath'
`$m = Move-OwnConsoleWindowTopRight -Width 1100 -Height 750
Start-Sleep -Milliseconds 600
`$h = [Win32Move]::GetConsoleWindow()
`$r = Get-WindowRect -Handle `$h
Set-Content -LiteralPath '$rectFile' -Encoding ascii -Value `"`$m|`$(`$r.Left)|`$(`$r.Top)|`$(`$r.Right-`$r.Left)|`$(`$r.Bottom-`$r.Top)`"
"@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    Start-Process conhost.exe -ArgumentList @('pwsh','-NoProfile','-EncodedCommand',$enc) -Wait
    Assert-True (Test-Path -LiteralPath $rectFile) 'placement: child reported its rect'
    $parts = (Get-Content -LiteralPath $rectFile -Raw).Trim() -split '\|'
    Assert-Equal 'True' $parts[0] 'placement: MoveWindow succeeded'
    Assert-True ([math]::Abs([int]$parts[1] - ($scr.Bounds.Right - 1100)) -le 8) "placement: left edge (got $($parts[1]), want $($scr.Bounds.Right - 1100))"
    Assert-True ([math]::Abs([int]$parts[2] - $scr.Bounds.Top) -le 8) "placement: top edge (got $($parts[2]), want $($scr.Bounds.Top))"
} finally {
    Remove-Item Env:\NETWATCH_TEST_IDLE_MS -ErrorAction SilentlyContinue
    Remove-TestStateRoot -Path $root
}

Complete-Tests
