# escalate.tests.ps1 - packet building/schema, batch cap, tier2 cycle with
# stub claude (clean / retry-then-failed / timeout), outcome handling
# (suppression, proposals, tier3 handoff), open-alarm suspension (F19),
# launch-failure backoff (F3).
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\escalate.psm1" -Force

$stub = Resolve-Path "$PSScriptRoot\stubs\stub-claude.cmd"
$tier3Stub = Resolve-Path "$PSScriptRoot\stubs\record-tier3.ps1"

function New-QueueEntry {
    param([string]$Name, [string]$Ip, [int]$Port, [datetime]$T0)
    return @{
        first_seen = $T0; last_seen = $T0.AddSeconds(30); samples = 2
        state_history = @('Established'); pending = $false
        enriched = @{ asn = 64500; as_name = 'TEST-AS'; as_country = 'ZZ' }
        snapshot = @{
            pid = 4242; name = $Name; image_path = $null; image_exists = $false
            command_line = ''; laddr = '192.168.1.10'; lport = 50001
            raddr = $Ip; rport = $Port; state = 'Established'
            direction = 'outbound'; domain = $null; attribution_source = 'none'
        }
    }
}

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root -Override @{
        # sec_per_key_budget 0 = clamp off: these scenarios drive tiny stub
        # runs under a 5s cap and need the raw batch_cap semantics
        tier2 = @{ claude_exe = "$stub"; wall_clock_cap_sec = 5; batch_cap = 20; sec_per_key_budget = 0 }
    }
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg
    $t0 = [datetime]::UtcNow.AddMinutes(-5)
    $health = @{ sni_capture = 'unavailable'; dns_etw = 'unavailable' }

    # --- packet builds and passes its own schema -----------------------------
    $queue = @{}
    $queue['proca|203.0.113.7|443'] = New-QueueEntry 'proca' '203.0.113.7' 443 $t0
    $queue['procb|203.0.113.8|8443'] = New-QueueEntry 'procb' '203.0.113.8' 8443 $t0.AddSeconds(10)
    $packet = Build-EscalationPacket -Keys @($queue.Keys) -Queue $queue -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow)
    Assert-Equal 2 $packet.connections.Count 'both keys packed'
    Assert-False $packet.overflow 'no overflow at 2 keys'
    Assert-Equal 64500 $packet.connections[0].remote.asn 'asn enrichment in packet'
    Assert-Equal 'test machine note' $packet.machine_notes[0] 'machine notes from config'

    # --- http-host attribution passes the packet schema ----------------------
    # (port-80 Host-header attribution, live alarm 20260827-143918 class)
    $queueH = @{}
    $qh = New-QueueEntry 'lsass' '104.18.21.213' 80 $t0
    $qh.snapshot.domain = 'yr1.c.lencr.org'
    $qh.snapshot.attribution_source = 'http-host'
    $queueH['lsass|yr1.c.lencr.org|80'] = $qh
    $packetH = Build-EscalationPacket -Keys @($queueH.Keys) -Queue $queueH -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow)
    Assert-Equal 'http-host' $packetH.connections[0].attribution.source 'http-host source survives the packet schema'

    # --- egress-change note rides in collector_health.notes ------------------
    # (task 2026-08-28: a fresh channel switch explains address rotation to
    # tier2; the schema's unused notes field carries it)
    $healthN = @{ sni_capture = 'ok'; dns_etw = 'ok'
                  egress_note = 'egress interface set changed 00:04:12 ago: [Ethernet, Tailscale] -> [Ethernet, OpenVPN Data Channel Offload, Tailscale]' }
    $packetN = Build-EscalationPacket -Keys @($queue.Keys) -Queue $queue -Config $cfg -Health $healthN -NowUtc ([datetime]::UtcNow)
    Assert-Equal $healthN.egress_note $packetN.collector_health.notes 'egress note lands in collector_health.notes'
    Assert-Null $packet.collector_health.PSObject.Properties['notes'] 'no notes field without a change'

    # --- batch cap + overflow ------------------------------------------------
    $bigQueue = @{}
    for ($i = 1; $i -le 25; $i++) {
        $bigQueue["proc$i|198.51.100.$i|443"] = New-QueueEntry "proc$i" "198.51.100.$i" 443 $t0.AddSeconds($i)
    }
    $bigPacket = Build-EscalationPacket -Keys @($bigQueue.Keys) -Queue $bigQueue -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow)
    Assert-Equal 20 $bigPacket.connections.Count 'batch cap 20'
    Assert-True $bigPacket.overflow 'overflow flagged'
    Assert-Equal 'proc1|198.51.100.1|443' $bigPacket.connections[0].key 'oldest first'

    # --- effective batch cap: wall-clock budget clamps the batch -------------
    # Live 2026-08-27: 7- and 14-key batches both hit tier2_timeout at the
    # 180s cap while <=3-key batches finished; batch_cap=20 was unsatisfiable.
    $prodRoot = Join-Path $root 'prodcfg'
    $null = New-Item -ItemType Directory -Path $prodRoot -Force
    $cfgProd = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $prodRoot)   # defaults: cap 180, batch 20, budget 30
    Assert-Equal 6 (Get-EffectiveBatchCap -Config $cfgProd) 'effective cap = floor(180/30)'
    $prodPacket = Build-EscalationPacket -Keys @($bigQueue.Keys) -Queue $bigQueue -Config $cfgProd -Health $health -NowUtc ([datetime]::UtcNow)
    Assert-Equal 6 $prodPacket.connections.Count 'packet clamped to effective cap'
    Assert-True $prodPacket.overflow 'overflow flagged on clamp'
    Assert-Equal 20 (Get-EffectiveBatchCap -Config $cfg) 'budget 0 disables the clamp (test seam)'

    # --- clean cycle end-to-end ----------------------------------------------
    $escState = New-EscalationState
    $env:STUB_MODE = 'clean'
    $result = Invoke-Tier2Cycle -Packet $packet -Config $cfg -ConfigPath $cfgPath
    Assert-Equal 'clean' $result.outcome 'clean outcome'
    Assert-Equal 'stub-session-123' $result.session_id 'session id'
    Complete-Tier2Outcome -Result $result -Packet $packet -Config $cfg -Queue $queue `
        -EscState $escState -Tier3Script $tier3Stub
    Assert-True (Test-Suppressed -Config $cfg -Key 'proca|203.0.113.7|443') 'key suppressed after CLEAN'
    Assert-Equal 0 $queue.Count 'queue cleared after CLEAN'
    $props = @(Get-Content (Join-Path $root 'state\proposals.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-Equal 1 $props.Count 'one proposal recorded'
    Assert-Equal 'stub-proposal' $props[0].proposal.id 'proposal content preserved'

    # --- retry then failed (F2) ----------------------------------------------
    $countFile = Join-Path $root 'stub-count.txt'
    $env:STUB_MODE = 'garbage'
    $env:STUB_COUNT_FILE = $countFile
    $queue2 = @{}
    $queue2['procc|203.0.113.9|443'] = New-QueueEntry 'procc' '203.0.113.9' 443 $t0
    $packet2 = Build-EscalationPacket -Keys @($queue2.Keys) -Queue $queue2 -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(1))
    $env:RECORD_TIER3_FILE = Join-Path $root 'tier3-call.json'
    $result2 = Invoke-Tier2Cycle -Packet $packet2 -Config $cfg -ConfigPath $cfgPath
    Assert-Equal 'failed' $result2.outcome 'garbage twice = failed'
    Assert-Equal 2 ([int](Get-Content $countFile)) 'exactly one retry (2 invocations)'
    Complete-Tier2Outcome -Result $result2 -Packet $packet2 -Config $cfg -Queue $queue2 `
        -EscState $escState -Tier3Script $tier3Stub
    $t3 = Get-Content $env:RECORD_TIER3_FILE -Raw | ConvertFrom-Json
    Assert-Equal 'tier2_failed' $t3.reason 'tier3 handoff reason tier2_failed'
    Assert-True $queue2['procc|203.0.113.9|443'].pending 'failed keys suspended as pending'
    Remove-Item Env:STUB_COUNT_FILE
    Remove-Item $env:RECORD_TIER3_FILE

    # --- timeout -> tier3 with reason tier2_timeout (F1) ---------------------
    $env:STUB_MODE = 'hang'
    $env:STUB_CHILD_PIDFILE = Join-Path $root 'sleeper.pid'
    $queue3 = @{}
    $queue3['procd|203.0.113.10|443'] = New-QueueEntry 'procd' '203.0.113.10' 443 $t0
    $packet3 = Build-EscalationPacket -Keys @($queue3.Keys) -Queue $queue3 -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(2))
    $result3 = Invoke-Tier2Cycle -Packet $packet3 -Config $cfg -ConfigPath $cfgPath
    Assert-Equal 'timeout' $result3.outcome 'timeout outcome'
    Complete-Tier2Outcome -Result $result3 -Packet $packet3 -Config $cfg -Queue $queue3 `
        -EscState $escState -Tier3Script $tier3Stub
    $t3 = Get-Content $env:RECORD_TIER3_FILE -Raw | ConvertFrom-Json
    Assert-Equal 'tier2_timeout' $t3.reason 'tier3 reason tier2_timeout'
    if (Test-Path $env:STUB_CHILD_PIDFILE) {
        $sp = [int](Get-Content $env:STUB_CHILD_PIDFILE)
        Stop-Process -Id $sp -Force -ErrorAction SilentlyContinue   # safety net cleanup
    }
    Remove-Item Env:STUB_CHILD_PIDFILE
    Remove-Item Env:STUB_MODE

    # --- D9 partial salvage: covered keys applied, ONLY uncovered to tier3 ---
    # (live 20260828-103245-317: full salvaged verdict was discarded and all
    # six connections raised tier3; the partial case is the general form)
    $env:STUB_MODE = 'hangpartial'
    $queueP = @{}
    $queueP['procp1|203.0.113.20|443'] = New-QueueEntry 'procp1' '203.0.113.20' 443 $t0
    $queueP['procp2|203.0.113.21|443'] = New-QueueEntry 'procp2' '203.0.113.21' 443 $t0.AddSeconds(5)
    $packetP = Build-EscalationPacket -Keys @($queueP.Keys) -Queue $queueP -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(6))
    $resultP = Invoke-Tier2Cycle -Packet $packetP -Config $cfg -ConfigPath $cfgPath
    Assert-Equal 'partial' $resultP.outcome 'partial salvage outcome'
    Assert-Equal 1 @($resultP.uncovered_keys).Count 'one key uncovered'
    Complete-Tier2Outcome -Result $resultP -Packet $packetP -Config $cfg -Queue $queueP `
        -EscState $escState -Tier3Script $tier3Stub
    Assert-True (Test-Suppressed -Config $cfg -Key 'procp1|203.0.113.20|443') 'covered clean key suppressed'
    Assert-False $queueP.ContainsKey('procp1|203.0.113.20|443') 'covered key left the queue'
    $t3 = Get-Content $env:RECORD_TIER3_FILE -Raw | ConvertFrom-Json
    Assert-Equal 'tier2_timeout' $t3.reason 'uncovered keys keep the F1 reason'
    Assert-Equal 'procp2|203.0.113.21|443' $t3.keys 'ONLY the uncovered key reached tier3'
    Assert-True $queueP['procp2|203.0.113.21|443'].pending 'uncovered key suspended as pending'
    Remove-Item Env:STUB_MODE

    # --- open-alarm suspension (F19) -----------------------------------------
    @{ reason = 'alarm'; keys = @('procd|203.0.113.10|443') } | ConvertTo-Json |
        Set-Content (Join-Path $root 'alarms\20260827-000003-open.marker')
    $suspended = @(Test-OpenAlarmKeys -Config $cfg -Keys @('procd|203.0.113.10|443', 'other|1.1.1.1|443'))
    Assert-Equal 1 $suspended.Count 'only marker keys suspended'
    Assert-Equal 'procd|203.0.113.10|443' $suspended[0] 'marker key identified'

    # --- F19 closing half: pending cleared once the marker is deleted --------
    Assert-True $queue3['procd|203.0.113.10|443'].pending 'precondition: key pending after alarm'
    $n = Reset-ClearedAlarmKeys -Config $cfg -Queue $queue3
    Assert-Equal 0 $n 'marker still open: nothing cleared'
    Assert-True $queue3['procd|203.0.113.10|443'].pending 'still pending while marker open'
    Remove-Item (Join-Path $root 'alarms\20260827-000003-open.marker')
    $n = Reset-ClearedAlarmKeys -Config $cfg -Queue $queue3
    Assert-Equal 1 $n 'one key cleared after marker removal'
    # marker deletion = operator resolution: the key must NOT stay primed for
    # instant re-escalation (2026-08-27 repeat-alarm loop: marker deleted
    # 18:36Z -> same keys re-escalated 18:36:45Z). Evict + cooldown instead.
    Assert-False $queue3.ContainsKey('procd|203.0.113.10|443') 'cleared key evicted from queue'
    Assert-True (Test-Suppressed -Config $cfg -Key 'procd|203.0.113.10|443') 'cleared key suppressed (cooldown)'

    # --- rc 0 with unreadable verdict file = failed run, not a crashed tick --
    # (deep-review deferred item, closed 2026-08-27: the rc-0 arm read the
    # verdict with no guard; a missing/corrupt file threw out of the cycle)
    $fakeRoot = Join-Path $root 'fake-code-root'
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $fakeRoot 'src\tier1')
    Set-Content -LiteralPath (Join-Path $fakeRoot 'src\tier1\invoke-tier2.ps1') -Value 'exit 0'
    $cfgFakePath = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = "$stub"; sec_per_key_budget = 0 }
        paths = @{ code_root = $fakeRoot }
    }
    $cfgFake = Get-NetwatchConfig -Path $cfgFakePath
    $queue5 = @{}
    $queue5['procf|203.0.113.12|443'] = New-QueueEntry 'procf' '203.0.113.12' 443 $t0
    $packet5 = Build-EscalationPacket -Keys @($queue5.Keys) -Queue $queue5 -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(4))
    $result5 = Invoke-Tier2Cycle -Packet $packet5 -Config $cfgFake -ConfigPath $cfgFakePath
    Assert-Equal 'failed' $result5.outcome 'unreadable verdict handled as failed (F2), no throw'
    $op = Get-Content (Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')) -Raw
    Assert-True ($op -match 'verdict unreadable') 'unreadable verdict logged'

    # --- rc 5 with NO uncovered_keys in the file (reviewer M2): must not
    # throw under StrictMode, must apply the verdict, must NOT launch tier3
    $fake5 = @'
param([string]$PacketPath, [string]$ConfigPath, [int]$Attempt = 1)
$ts = [IO.Path]::GetFileName($PacketPath) -replace '-packet\.json$', ''
$doc = @{ session_id = 'fake5'; verdict = @{
    verdict = 'CLEAN'; summary = 's'
    connections = @(@{ key = 'procg|203.0.113.13|443'; assessment = 'clean'
                       reasons = @('r'); evidence = @('e') }) } }
$doc | ConvertTo-Json -Depth 6 | Set-Content (Join-Path (Split-Path $PacketPath -Parent) "$ts-verdict.json")
exit 5
'@
    Set-Content -LiteralPath (Join-Path $fakeRoot 'src\tier1\invoke-tier2.ps1') -Value $fake5
    $queue6 = @{}
    $queue6['procg|203.0.113.13|443'] = New-QueueEntry 'procg' '203.0.113.13' 443 $t0
    $packet6 = Build-EscalationPacket -Keys @($queue6.Keys) -Queue $queue6 -Config $cfg -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(7))
    $result6 = Invoke-Tier2Cycle -Packet $packet6 -Config $cfgFake -ConfigPath $cfgFakePath
    Assert-Equal 'partial' $result6.outcome 'rc5 without uncovered_keys parsed defensively'
    Assert-Equal 0 @($result6.uncovered_keys).Count 'missing uncovered_keys reads as empty'
    Remove-Item $env:RECORD_TIER3_FILE -ErrorAction SilentlyContinue
    Complete-Tier2Outcome -Result $result6 -Packet $packet6 -Config $cfg -Queue $queue6 `
        -EscState $escState -Tier3Script $tier3Stub
    Assert-True (Test-Suppressed -Config $cfg -Key 'procg|203.0.113.13|443') 'covered key applied'
    Assert-False (Test-Path $env:RECORD_TIER3_FILE) 'no tier3 launch when nothing is uncovered'

    # --- launch failure backoff (F3) -----------------------------------------
    $cfgBadPath = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = (Join-Path $root 'no-claude.exe') }
    }
    $cfgBad = Get-NetwatchConfig -Path $cfgBadPath
    $queue4 = @{}
    $queue4['proce|203.0.113.11|443'] = New-QueueEntry 'proce' '203.0.113.11' 443 $t0
    $packet4 = Build-EscalationPacket -Keys @($queue4.Keys) -Queue $queue4 -Config $cfgBad -Health $health -NowUtc ([datetime]::UtcNow.AddSeconds(3))
    $result4 = Invoke-Tier2Cycle -Packet $packet4 -Config $cfgBad -ConfigPath $cfgBadPath
    Assert-Equal 'launch_failed' $result4.outcome 'launch failure detected'
    $escState2 = New-EscalationState
    Complete-Tier2Outcome -Result $result4 -Packet $packet4 -Config $cfgBad -Queue $queue4 `
        -EscState $escState2 -Tier3Script $tier3Stub
    Assert-Equal 1 $escState2.backoff_idx 'backoff advanced'
    Assert-True ($escState2.next_allowed -gt [datetime]::UtcNow.AddMinutes(9)) 'first backoff ~10 min'
    Complete-Tier2Outcome -Result $result4 -Packet $packet4 -Config $cfgBad -Queue $queue4 `
        -EscState $escState2 -Tier3Script $tier3Stub
    Assert-True ($escState2.next_allowed -gt [datetime]::UtcNow.AddMinutes(29)) 'second backoff ~30 min'
}
finally {
    Remove-Item Env:STUB_MODE, Env:STUB_COUNT_FILE, Env:STUB_CHILD_PIDFILE, Env:RECORD_TIER3_FILE -ErrorAction SilentlyContinue
    Remove-TestStateRoot $root
}
Complete-Tests
