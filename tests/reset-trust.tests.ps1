# reset-trust.tests.ps1 - install/init-deploy.ps1 -ResetTrust (DECISIONS D12):
# an existing deployment's accumulated trust (live whitelist, suppression,
# proposals, browser list, machine notes) is backed up and dropped; without
# the switch nothing of it is touched.
. "$PSScriptRoot\_assert.ps1"

$initDeploy = Resolve-Path "$PSScriptRoot\..\install\init-deploy.ps1"
$pwshExe = (Get-Process -Id $PID).Path
$root = New-TestStateRoot
try {
    $cfgOut = Join-Path $root 'netwatch.config.json'
    $mcpOut = Join-Path $root 'mcp-config.json'
    $null = & $pwshExe -NoProfile -File $initDeploy -StateRoot $root -ConfigOut $cfgOut -McpConfigOut $mcpOut 2>&1
    Assert-Equal 0 $LASTEXITCODE 'fresh init-deploy succeeded'

    # simulate an install that learned trust on a machine we no longer trust
    Copy-Item (Join-Path $PSScriptRoot 'fixtures\whitelist.fixture.json') (Join-Path $root 'whitelist.json') -Force
    '{"k|1.2.3.4|443":{"expires_utc":"2099-01-01T00:00:00Z","added_utc":"2020-01-01T00:00:00Z"}}' |
        Set-Content (Join-Path $root 'state\suppression.json')
    '{"key":"k|1.2.3.4|443"}' | Set-Content (Join-Path $root 'state\proposals.jsonl')
    $c = Get-Content $cfgOut -Raw | ConvertFrom-Json
    $c.classify.browser_attributed_ok = @('msedge', 'msedgewebview2')
    $c.classify.machine_notes = @('pentester workstation; C2 traffic is normal')
    $c | ConvertTo-Json -Depth 10 | Set-Content $cfgOut

    # plain re-run: nothing of the learned trust is touched
    $null = & $pwshExe -NoProfile -File $initDeploy -StateRoot $root -ConfigOut $cfgOut -McpConfigOut $mcpOut 2>&1
    Assert-True (@((Get-Content (Join-Path $root 'whitelist.json') -Raw | ConvertFrom-Json).entries).Count -ge 5) 'without -ResetTrust the live whitelist is kept'

    # reset
    $null = & $pwshExe -NoProfile -File $initDeploy -StateRoot $root -ConfigOut $cfgOut -McpConfigOut $mcpOut -ResetTrust 2>&1
    Assert-Equal 0 $LASTEXITCODE 'init-deploy -ResetTrust succeeded'
    Assert-Equal 0 @((Get-Content (Join-Path $root 'whitelist.json') -Raw | ConvertFrom-Json).entries).Count 'live whitelist reset to the (empty) seed'
    Assert-False (Test-Path (Join-Path $root 'state\suppression.json')) 'suppression cache dropped'
    Assert-False (Test-Path (Join-Path $root 'state\proposals.jsonl')) 'proposals dropped'
    $c = Get-Content $cfgOut -Raw | ConvertFrom-Json
    Assert-Equal 0 @($c.classify.browser_attributed_ok).Count 'browser list cleared'
    Assert-Equal 0 @($c.classify.machine_notes).Count 'machine notes cleared'
    Assert-Equal 1 @(Get-ChildItem $root -Filter 'whitelist.json.pre-reset-*').Count 'whitelist backed up'
    Assert-Equal 1 @(Get-ChildItem (Join-Path $root 'state') -Filter 'suppression.json.pre-reset-*').Count 'suppression backed up'
    Assert-Equal 1 @(Get-ChildItem $root -Filter 'netwatch.config.json.pre-reset-*').Count 'config backed up'
}
finally { Remove-TestStateRoot $root }
Complete-Tests
