# e2e-suppression.tests.ps1 - D1 property across two full netwatch runs on a
# SHARED state root: keys cleaned (and thus suppressed) in run 1 must not be
# re-escalated by run 2. Live traffic may add NEW keys in run 2 - that is
# legitimate; the assertion is strictly about run-1 keys.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$netwatch = Resolve-Path "$PSScriptRoot\..\src\tier1\netwatch.ps1"
$stub = Resolve-Path "$PSScriptRoot\stubs\stub-claude.cmd"

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = "$stub"; wall_clock_cap_sec = 30 }
    }
    $env:STUB_MODE = 'clean'
    try {
        & pwsh -NoProfile -File $netwatch -ConfigPath $cfgPath -MaxTicks 2 -TickDelaySec 1 -NoMutex | Out-Null
        Assert-Equal 0 $LASTEXITCODE 'run 1 completed'
        $escDir = Join-Path $root 'escalations'
        $run1Packets = @(Get-ChildItem $escDir -Filter '*-packet.json' -ErrorAction SilentlyContinue)
        if ($run1Packets.Count -eq 0) {
            Skip-Test 'run 1 produced no residuals (no live connections here) - suppression e2e not exercised'
            Complete-Tests
        }
        $run1Keys = @($run1Packets | ForEach-Object {
                (Get-Content $_.FullName -Raw | ConvertFrom-Json).connections | ForEach-Object key
            } | Select-Object -Unique)
        Assert-True ($run1Keys.Count -ge 1) 'run 1 escalated at least one key'

        # all run-1 keys must now be suppressed
        $sup = Get-Content (Join-Path $root 'state\suppression.json') -Raw | ConvertFrom-Json
        foreach ($k in $run1Keys) {
            Assert-NotNull $sup.PSObject.Properties[$k] "run-1 key suppressed: $k"
        }

        & pwsh -NoProfile -File $netwatch -ConfigPath $cfgPath -MaxTicks 2 -TickDelaySec 1 -NoMutex | Out-Null
        Assert-Equal 0 $LASTEXITCODE 'run 2 completed'
        $run2Packets = @(Get-ChildItem $escDir -Filter '*-packet.json' |
                Where-Object { $_.FullName -notin @($run1Packets | ForEach-Object FullName) })
        $reEscalated = @($run2Packets | ForEach-Object {
                (Get-Content $_.FullName -Raw | ConvertFrom-Json).connections | ForEach-Object key
            } | Where-Object { $_ -in $run1Keys })
        Assert-Equal 0 $reEscalated.Count "no run-1 key re-escalated in run 2 (violators: $($reEscalated -join ', '))"
        Write-Host "e2e: run1 cleaned $($run1Keys.Count) key(s); run2 packets: $($run2Packets.Count) (new keys only)"
    }
    finally {
        Remove-Item Env:STUB_MODE -ErrorAction SilentlyContinue
    }
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
