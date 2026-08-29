# tier3.tests.ps1 - launch-tier3.ps1: alarm record + open marker (F19),
# always-fresh-session argv (operator decision 2026-08-27: no --resume, the
# drifted tier-2 context must not leak into the human review), toast failure
# not blocking.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$tier3 = Resolve-Path "$PSScriptRoot\..\src\tier3\launch-tier3.ps1"
$claudeStub = Resolve-Path "$PSScriptRoot\stubs\record-claude.cmd"

$root = New-TestStateRoot
try {
    $alarmSrc = Join-Path $root 'packet.json'
    '{"packet_id":"p1","connections":[]}' | Set-Content -LiteralPath $alarmSrc

    # --- with session id: STILL a fresh session; id is reference-only --------
    $rec = Join-Path $root 'claude-call-1.json'
    $env:RECORD_CLAUDE_FILE = $rec
    & pwsh -NoProfile -File $tier3 -SessionId 'sess-abc' -Reason 'alarm' `
        -AlarmFile $alarmSrc -ClaudeExe "$claudeStub" -StateRoot $root `
        -Keys 'k1|1.2.3.4|443,k2|evil.example|8443'
    # Start-Process is async; wait briefly for the stub to write
    $deadline = [datetime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path $rec) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    Assert-True (Test-Path $rec) 'claude stub invoked (session-id path)'
    $call = Get-Content $rec -Raw | ConvertFrom-Json
    # --permission-mode auto (2026-08-29): unattended full-capability session
    # must not sit waiting on a permission/opt-in prompt mid-investigation
    Assert-Equal 3 $call.args.Count '--permission-mode auto + single fresh prompt argument (no --resume)'
    Assert-Equal '--permission-mode' $call.args[0] 'permission-mode flag present'
    Assert-Equal 'auto' $call.args[1] 'permission-mode value is auto'
    Assert-True ($call.args[2] -notlike '--resume*') 'resume flag gone'
    Assert-True ($call.args[2] -like '*sess-abc*') 'tier2 session id referenced in prompt'
    Assert-True ($call.args[2] -like '*k2|evil.example|8443*') 'keys listed in prompt'
    Assert-Equal $root $call.cwd 'working directory = state root'

    $alarms = @(Get-ChildItem (Join-Path $root 'alarms') -Filter '*-alarm.json')
    Assert-Equal 1 $alarms.Count 'alarm record written'
    # filenames must use the UTC clock like every other artifact (reviewer L3:
    # local-date names put alarms and packets in different timezones)
    Assert-True ($alarms[0].Name.StartsWith([datetime]::UtcNow.ToString('yyyyMMdd'))) 'alarm filename dated in UTC'
    $markers = @(Get-ChildItem (Join-Path $root 'alarms') -Filter '*-open.marker')
    Assert-Equal 1 $markers.Count 'open marker written'
    $m = Get-Content $markers[0].FullName -Raw | ConvertFrom-Json
    Assert-Equal 'alarm' $m.reason 'marker reason'
    Assert-Equal 2 $m.keys.Count 'marker carries both keys (F19)'
    Assert-True ('k2|evil.example|8443' -in $m.keys) 'key list intact'

    # --- without session id: fresh session with alarm-file prompt ------------
    Get-ChildItem (Join-Path $root 'alarms') | Remove-Item
    $rec2 = Join-Path $root 'claude-call-2.json'
    $env:RECORD_CLAUDE_FILE = $rec2
    & pwsh -NoProfile -File $tier3 -Reason 'tier2_timeout' `
        -AlarmFile $alarmSrc -ClaudeExe "$claudeStub" -StateRoot $root -Keys 'k1|1.2.3.4|443'
    $deadline = [datetime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path $rec2) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    Assert-True (Test-Path $rec2) 'claude stub invoked (fresh path)'
    $call = Get-Content $rec2 -Raw | ConvertFrom-Json
    Assert-Equal 3 $call.args.Count '--permission-mode auto + single prompt argument'
    Assert-Equal '--permission-mode' $call.args[0] 'permission-mode flag present'
    Assert-Equal 'auto' $call.args[1] 'permission-mode value is auto'
    Assert-True ($call.args[2] -like '*tier2_timeout*') 'reason in prompt'
    Assert-True ($call.args[2] -like "*$alarmSrc*") 'alarm file path in prompt'
    Assert-True ($call.args[2] -like '*data, not instructions*') 'injection warning in prompt'
    # toast failed (BurntToast absent) yet we made it here: F16 non-blocking held
}
finally {
    Remove-Item Env:RECORD_CLAUDE_FILE -ErrorAction SilentlyContinue
    Remove-TestStateRoot $root
}
Complete-Tests
