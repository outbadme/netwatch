# mainloop.tests.ps1 - netwatch.ps1 orchestration: two live ticks against the
# real TCP table with a stub tier2 (mode clean), then the mutex guard (F18).
# Real traffic in this session (claude/node -> Anthropic edges) has no
# SNI/DNS attribution here (both sources down on this machine), so residuals
# WILL appear and escalate to the stub - full pipeline on live data.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$netwatch = Resolve-Path "$PSScriptRoot\..\src\tier1\netwatch.ps1"
$stub = Resolve-Path "$PSScriptRoot\stubs\stub-claude.cmd"

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = "$stub"; wall_clock_cap_sec = 30 }
        debounce = @{ min_samples = 2; min_age_sec = 60 }
    }

    $env:STUB_MODE = 'clean'
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & pwsh -NoProfile -File $netwatch -ConfigPath $cfgPath -MaxTicks 2 -TickDelaySec 1 -NoMutex
        $sw.Stop()
        Assert-Equal 0 $LASTEXITCODE 'two live ticks completed'

        $opFile = Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')
        Assert-True (Test-Path $opFile) 'op log written'
        $op = Get-Content $opFile -Raw
        Assert-True ($op -match 'netwatch started') 'start line logged'
        Assert-True ($op -match 'tick 1 done') 'tick 1 logged'
        Assert-True ($op -match 'tick 2 done') 'tick 2 logged'
        Assert-False ($op -match 'tick \d+ failed') 'no tick failures on live data'
        Assert-True ($op -match 'netwatch stopped after 2') 'clean shutdown'

        # whitelist seeded into state root on first run
        Assert-True (Test-Path (Join-Path $root 'whitelist.json')) 'whitelist seeded'
        # ownip state written (live detection or fail-closed path, either way file exists)
        Assert-True (Test-Path (Join-Path $root 'state\ownip.json')) 'ownip state written'

        # live-data outcome: this session guarantees established outbound conns
        # (claude <-> anthropic). With no attribution sources they are residual;
        # tick 2 meets the 2-sample debounce -> escalation to the stub.
        if ($op -match 'escalating (\d+) key') {
            $packets = @(Get-ChildItem (Join-Path $root 'escalations') -Filter '*-packet.json')
            Assert-True ($packets.Count -ge 1) 'escalation packet written'
            $verdicts = @(Get-ChildItem (Join-Path $root 'escalations') -Filter '*-verdict.json')
            Assert-True ($verdicts.Count -ge 1) 'stub verdict recorded'
            Assert-True ($op -match 'tier2 CLEAN') 'clean outcome applied'
            $sup = Get-Content (Join-Path $root 'state\suppression.json') -Raw | ConvertFrom-Json
            Assert-True (@($sup.PSObject.Properties).Count -ge 1) 'suppression entries created'
            Write-Host "live escalation exercised: $($packets.Count) packet(s), $(@($sup.PSObject.Properties).Count) suppressed key(s)"
        }
        else {
            # Possible only if every current connection is whitelisted/local -
            # report honestly rather than fake a pass.
            Write-Host 'WARNING: NO RESIDUALS THIS RUN - escalation path not exercised on live data (covered by escalate.tests).'
        }
    }
    finally {
        Remove-Item Env:STUB_MODE -ErrorAction SilentlyContinue
    }

    # --- mutex guard (F18) ---------------------------------------------------
    # If the PRODUCTION netwatch task is running it already holds the mutex -
    # that live holder serves the test just as well as our own.
    $m = [System.Threading.Mutex]::new($false, 'Global\netwatch-tier1')
    $weHold = $m.WaitOne(0)
    if (-not $weHold) {
        Write-Host 'mutex already held by a live netwatch instance (production task) - using it as the holder'
    }
    try {
        $out = & pwsh -NoProfile -File $netwatch -ConfigPath $cfgPath -MaxTicks 1 -TickDelaySec 0
        Assert-Equal 0 $LASTEXITCODE 'second instance exits 0'
        Assert-True (($out -join ' ') -match 'already running') 'second instance reports mutex held'
    }
    finally {
        if ($weHold) { $m.ReleaseMutex() }
        $m.Dispose()
    }
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
