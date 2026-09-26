# escalate.psm1 - escalation-packet builder, Tier-2 invocation cycle (with
# retry, F2), verdict outcome handling (CLEAN suppression/proposals per D1,
# ALARM/timeout/failure -> Tier 3), open-alarm key suspension (F19), launch
# failure backoff (F3).

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'state.psm1')
Import-Module (Join-Path $PSScriptRoot 'toast.psm1')

function New-EscalationState {
    return @{
        last_tier2  = [datetime]::MinValue
        backoff_idx = 0                 # F3 ladder position (10 -> 30 -> 60 min)
        next_allowed = [datetime]::MinValue
    }
}

function Get-EffectiveBatchCap {
    # batch_cap alone proved unsatisfiable: live 2026-08-27 the 7- and 14-key
    # batches both hit tier2_timeout at the 180s wall clock while <=3-key
    # batches finished. Clamp the batch to what the cap can actually judge:
    # floor(wall_clock_cap_sec / sec_per_key_budget), at least 1, never above
    # batch_cap. Budget default 30s/key (live: ~25-40s each); 0 disables the
    # clamp (test seam for tiny stub caps).
    param([Parameter(Mandatory)] $Config)
    $cap = $Config.tier2.batch_cap
    $budget = 30
    if ($Config.tier2.PSObject.Properties['sec_per_key_budget']) {
        $budget = $Config.tier2.sec_per_key_budget
    }
    if ($budget -le 0) { return $cap }
    return [math]::Max(1, [math]::Min($cap, [math]::Floor($Config.tier2.wall_clock_cap_sec / $budget)))
}

function Build-EscalationPacket {
    # Packet per schemas/escalation-packet.schema.json from residual-queue
    # entries. Applies the batch cap (overflow flagged); validates against the
    # schema before returning (a malformed packet must fail HERE, loudly).
    param(
        [Parameter(Mandatory)] [string[]]$Keys,
        [Parameter(Mandatory)] [hashtable]$Queue,
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] $Health,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    $cap = Get-EffectiveBatchCap -Config $Config
    $ordered = @($Keys | Where-Object { $Queue.ContainsKey($_) } |
        Sort-Object { $Queue[$_].first_seen })
    $batch = @($ordered | Select-Object -First $cap)

    $connections = foreach ($k in $batch) {
        $q = $Queue[$k]
        $c = $q.snapshot
        $proc = [ordered]@{ pid = $c.pid; name = $c.name }
        if ($c.image_path) {
            $proc.image_path   = $c.image_path
            $proc.image_exists = [bool]$c.image_exists
        }
        if ($c.command_line) { $proc.command_line = $c.command_line }
        if ($c.ContainsKey('identity') -and $c.identity) { $proc.identity = $c.identity }
        $remote = [ordered]@{ ip = $c.raddr; port = $c.rport }
        if ($q.enriched) {
            if ($null -ne $q.enriched.asn)        { $remote.asn = $q.enriched.asn }
            if ($q.enriched.as_name)              { $remote.as_name = $q.enriched.as_name }
            if ($q.enriched.as_country)           { $remote.as_country = $q.enriched.as_country }
        }
        $att = [ordered]@{ source = $c.attribution_source }
        if ($c.domain) { $att.domain = $c.domain }
        $entry = [ordered]@{
            key            = $k
            process        = $proc
            remote         = $remote
            local          = [ordered]@{ ip = $c.laddr; port = $c.lport }
            direction      = $c.direction
            state_history  = @($q.state_history)
            first_seen_utc = $q.first_seen.ToString('o')
            last_seen_utc  = $q.last_seen.ToString('o')
            samples_seen   = $q.samples
            attribution    = $att
        }
        if ($q.ContainsKey('prior_history') -and $q.prior_history) { $entry.prior_history = $q.prior_history }
        [pscustomobject]$entry
    }

    $ch = [ordered]@{
        sni_capture = $Health.sni_capture
        dns_etw     = $Health.dns_etw
    }
    # egress-change note (2026-08-28): a fresh channel switch (VPN/proxy
    # up/down) explains sudden address rotation - tier2 must see it as
    # context, not treat the rotation as evidence
    if ($Health.ContainsKey('egress_note') -and $Health.egress_note) { $ch.notes = [string]$Health.egress_note }
    $packet = [pscustomobject][ordered]@{
        packet_id        = $NowUtc.ToString('yyyyMMdd-HHmmss-fff')   # ms: no filename collisions on immediate triggers
        created_utc      = $NowUtc.ToString('o')
        collector_health = [pscustomobject]$ch
        machine_notes    = @($Config.classify.machine_notes)
        overflow         = ($ordered.Count -gt $cap)
        connections      = @($connections)
    }

    $schema = Join-Path $Config.paths.code_root 'schemas\escalation-packet.schema.json'
    $json = $packet | ConvertTo-Json -Depth 10
    if (-not (Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue)) {
        throw "built escalation packet failed its own schema - refusing to send"
    }
    return $packet
}

function Invoke-Tier2Cycle {
    # Writes the packet, launches invoke-tier2.ps1 under the cap, retries once
    # on invalid output (F2). Returns @{ outcome; verdict; session_id;
    # packet_file }. Outcomes: clean | alarm | timeout | failed | launch_failed.
    param(
        [Parameter(Mandatory)] $Packet,
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$ConfigPath
    )
    $escDir = Join-Path $Config.paths.state_root 'escalations'
    $packetFile = Join-Path $escDir "$($Packet.packet_id)-packet.json"
    $Packet | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $packetFile -Encoding utf8

    $invoke = Join-Path $Config.paths.code_root 'src\tier1\invoke-tier2.ps1'
    $result = @{ outcome = $null; verdict = $null; session_id = $null; packet_file = $packetFile
                 uncovered_keys = @() }

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        & pwsh -NoProfile -File $invoke -PacketPath $packetFile -ConfigPath $ConfigPath -Attempt $attempt | Out-Null
        $rc = $LASTEXITCODE
        switch ($rc) {
            0 {
                # rc 0 promises a verdict file, but a missing/corrupt one must
                # degrade to the F2 path, not throw out of the tick
                $vf = Join-Path $escDir "$($Packet.packet_id)-verdict.json"
                $v = $null
                try { $v = Get-Content -LiteralPath $vf -Raw -ErrorAction Stop | ConvertFrom-Json }
                catch {
                    Write-OpLog -Config $Config -Level WARN -Message "tier2 rc 0 but verdict unreadable (attempt $attempt): $($_.Exception.Message)"
                }
                if ($v) {
                    $result.session_id = $v.session_id
                    $result.verdict    = $v.verdict
                    $result.outcome    = if ($v.verdict.verdict -eq 'ALARM') { 'alarm' } else { 'clean' }
                    return $result
                }
                # fall through the loop like invalid output (F2)
            }
            2 { $result.outcome = 'timeout';       return $result }   # F1: no retry, straight to Tier 3
            3 { $result.outcome = 'launch_failed'; return $result }   # F3
            6 { $result.outcome = 'quota_exhausted'; return $result } # F2 does NOT apply here: an instant
                                                                       # retry cannot succeed against a live
                                                                       # 429, and this is capacity, not a
                                                                       # finding, so it must not reach Tier 3
            5 {
                # D9 partial salvage: the timed-out run's verdict validated for
                # a subset of keys; the launcher wrote them + uncovered_keys
                $vf = Join-Path $escDir "$($Packet.packet_id)-verdict.json"
                $v = $null
                try { $v = Get-Content -LiteralPath $vf -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
                if ($v) {
                    $result.session_id     = $v.session_id
                    $result.verdict        = $v.verdict
                    # defensive: the field is absent on some writer paths
                    # (reviewer M2) - StrictMode must not throw here. NB: an
                    # if-expression yielding @() assigns $null, hence the
                    # explicit default + null/empty filtering.
                    $result.uncovered_keys = @()
                    if ($v.PSObject.Properties['uncovered_keys']) {
                        $result.uncovered_keys = @(@($v.uncovered_keys) | Where-Object { $_ })
                    }
                    $result.outcome        = 'partial'
                }
                else { $result.outcome = 'timeout' }   # unreadable salvage = plain F1
                return $result
            }
            default {
                Write-OpLog -Config $Config -Level WARN -Message "tier2 invalid output (attempt $attempt, rc $rc)"
                # F2: loop once more; second failure falls through
            }
        }
    }
    $result.outcome = 'failed'                                        # F2 second failure
    return $result
}

function Complete-Tier2Outcome {
    # Applies the outcome. CLEAN: toast + 24h suppression + proposals (D1) +
    # queue cleanup. ALARM/timeout/failed: Tier-3 handoff (keys stay pending =
    # suspended until the human clears the alarm marker, F19). launch_failed:
    # toast + F3 backoff ladder. quota_exhausted: same backoff-ladder shape as
    # launch_failed (reuses EscState.backoff_idx/next_allowed - no new state),
    # but non-urgent toast and no Tier-3 (capacity, not a finding; live
    # 2026-08-27 this used to false-escalate as tier2_failed within seconds).
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] $Packet,
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [hashtable]$Queue,
        [Parameter(Mandatory)] [hashtable]$EscState,
        [string]$Tier3Script
    )
    if (-not $Tier3Script) {
        $Tier3Script = Join-Path $Config.paths.code_root 'src\tier3\launch-tier3.ps1'
    }
    $keys = @($Packet.connections | ForEach-Object key)

    # tier3 window lifecycle settings (docs/plans/TIER3-IDLE-CLOSE-20260828.md).
    # StrictMode-safe: the whole section and each key are optional; absent
    # means the launcher's own defaults (5 min idle close, 1100x750 window,
    # <Desktop>\netwatch reports).
    $t3cfg = if ($Config.PSObject.Properties['tier3']) { $Config.tier3 } else { $null }
    $t3opt = {
        param($name, $default)
        if ($t3cfg -and $t3cfg.PSObject.Properties[$name]) { $t3cfg.$name } else { $default }
    }
    $t3Idle  = & $t3opt 'idle_close_min' 5
    $t3W     = & $t3opt 'window_width_px' 1100
    $t3H     = & $t3opt 'window_height_px' 750
    $t3Dir   = & $t3opt 'report_dir' ''
    $t3Extra = @('-IdleCloseMin', $t3Idle, '-WindowWidthPx', $t3W, '-WindowHeightPx', $t3H, '-ReportDir', $t3Dir)

    switch ($Result.outcome) {
        'clean' {
            foreach ($c in @($Result.verdict.connections)) {
                Add-Suppression -Config $Config -Key $c.key -TtlHours $Config.suppression_ttl_hours
                if ($c.PSObject.Properties['proposed_whitelist_entry'] -and $c.proposed_whitelist_entry) {
                    Add-Proposal -Config $Config -Key $c.key -Proposal $c.proposed_whitelist_entry `
                        -PacketId $Packet.packet_id
                }
                $Queue.Remove($c.key)
            }
            $EscState.backoff_idx = 0
            $null = Send-NetwatchToast -Config $Config -Title 'netwatch: CLEAN' `
                -Message "Tier-2 cleared $($keys.Count) connection(s). Suppressed 24h; proposals await review."
            Write-OpLog -Config $Config -Level INFO -Message "tier2 CLEAN for $($keys -join ', ')"
        }
        'partial' {
            # D9: salvaged verdict applies to its validated connections; ONLY
            # the uncovered (plus any covered-suspicious) keys reach Tier-3.
            # Nothing unvalidated is ever treated as clean.
            $suspKeys = @()
            foreach ($c in @($Result.verdict.connections)) {
                if ($c.assessment -eq 'clean') {
                    Add-Suppression -Config $Config -Key $c.key -TtlHours $Config.suppression_ttl_hours
                    if ($c.PSObject.Properties['proposed_whitelist_entry'] -and $c.proposed_whitelist_entry) {
                        Add-Proposal -Config $Config -Key $c.key -Proposal $c.proposed_whitelist_entry `
                            -PacketId $Packet.packet_id
                    }
                    $Queue.Remove($c.key)
                }
                else { $suspKeys += $c.key }
            }
            $t3Keys = @($Result.uncovered_keys) + $suspKeys
            foreach ($k in $t3Keys) { if ($Queue.ContainsKey($k)) { $Queue[$k].pending = $true } }
            $EscState.backoff_idx = 0
            if (-not $t3Keys.Count) {
                # nothing uncovered and nothing suspicious: fully applied,
                # a tier3 window with an empty key list would be noise
                Write-OpLog -Config $Config -Level INFO -Message "tier2 partial salvage (D9): all $(@($Result.verdict.connections).Count) key(s) applied, no tier3 needed"
                return
            }
            $reason = if ($suspKeys.Count) { 'alarm' } else { 'tier2_timeout' }
            $t3Args = @('-NoProfile', '-File', $Tier3Script,
                '-Reason', $reason,
                '-AlarmFile', $Result.packet_file,
                '-ClaudeExe', $Config.tier2.claude_exe,
                '-StateRoot', $Config.paths.state_root,
                '-Keys', ($t3Keys -join ','))
            $t3Args += $t3Extra
            if ($Result.session_id) { $t3Args += @('-SessionId', $Result.session_id) }
            & pwsh @t3Args
            Write-OpLog -Config $Config -Level ERROR -Message "tier2 partial salvage (D9): $(@($Result.verdict.connections).Count) key(s) applied, tier3 reason=$reason for $($t3Keys -join ', ')"
        }
        { $_ -in 'alarm', 'timeout', 'failed' } {
            $reason = switch ($Result.outcome) {
                'alarm'   { 'alarm' }
                'timeout' { 'tier2_timeout' }
                'failed'  { 'tier2_failed' }
            }
            foreach ($k in $keys) { if ($Queue.ContainsKey($k)) { $Queue[$k].pending = $true } }
            $EscState.backoff_idx = 0
            $t3Args = @('-NoProfile', '-File', $Tier3Script,
                '-Reason', $reason,
                '-AlarmFile', $Result.packet_file,
                '-ClaudeExe', $Config.tier2.claude_exe,
                '-StateRoot', $Config.paths.state_root,
                '-Keys', ($keys -join ','))
            $t3Args += $t3Extra
            if ($Result.session_id) { $t3Args += @('-SessionId', $Result.session_id) }
            & pwsh @t3Args
            Write-OpLog -Config $Config -Level ERROR -Message "tier3 launched, reason=$reason keys=$($keys -join ', ')"
        }
        'launch_failed' {
            # F3: claude CLI unusable - human must fix; residuals keep queueing
            $ladder = @(10, 30, 60)
            $delay = $ladder[[math]::Min($EscState.backoff_idx, $ladder.Count - 1)]
            $EscState.backoff_idx++
            $EscState.next_allowed = [datetime]::UtcNow.AddMinutes($delay)
            $null = Send-NetwatchToast -Config $Config -Urgent -Title 'netwatch: tier2 unavailable' `
                -Message "claude launch failed; retry in $delay min. Residuals keep accumulating."
            Write-OpLog -Config $Config -Level ERROR -Message "tier2 launch failed; backoff $delay min"
        }
        'quota_exhausted' {
            # Capacity, not a finding: no Tier-3, no marker, no queue change -
            # the same keys are simply escalatable again once next_allowed
            # passes. Ladder is longer than F3's (quota resets run for hours,
            # not minutes; live 2026-08-28 the observed reset was ~6h away) and
            # the toast is non-urgent, since nothing here needs a human's
            # immediate attention - only that it happened, in case it persists.
            $ladder = @(15, 60, 180)
            $delay = $ladder[[math]::Min($EscState.backoff_idx, $ladder.Count - 1)]
            $EscState.backoff_idx++
            $EscState.next_allowed = [datetime]::UtcNow.AddMinutes($delay)
            $null = Send-NetwatchToast -Config $Config -Title 'netwatch: tier2 quota' `
                -Message "Subscription session limit hit; retrying in $delay min automatically. No action needed."
            Write-OpLog -Config $Config -Level WARN -Message "tier2 quota exhausted; backoff $delay min, keys stay queued: $($keys -join ', ')"
        }
    }
}

function Reset-ClearedAlarmKeys {
    # F19 closing half: the human deleting the open-marker IS the alarm
    # resolution. Cleared keys are evicted from the queue and get the standard
    # suppression TTL as a cooldown. Merely flipping pending=false left a
    # fully-primed entry that re-escalated on the next tick (2026-08-27
    # repeat-alarm loop: markers deleted ~18:36Z, same keys re-escalated
    # 18:36:45Z and toasted the operator every ~30 min).
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [hashtable]$Queue
    )
    $pendingKeys = @($Queue.Keys | Where-Object { $Queue[$_].pending })
    if (-not $pendingKeys) { return 0 }
    $stillSuspended = @(Test-OpenAlarmKeys -Config $Config -Keys $pendingKeys)
    $cleared = 0
    foreach ($k in $pendingKeys) {
        if ($k -notin $stillSuspended) {
            $Queue.Remove($k)
            Add-Suppression -Config $Config -Key $k -TtlHours $Config.suppression_ttl_hours
            $cleared++
            Write-OpLog -Config $Config -Level INFO -Message "alarm cleared for $k - evicted, suppressed $($Config.suppression_ttl_hours)h (operator resolution)"
        }
    }
    return $cleared
}

function Test-OpenAlarmKeys {
    # Keys currently covered by an open alarm marker (F19) - excluded from
    # re-escalation until the human removes the marker.
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$Keys
    )
    $suspended = [System.Collections.Generic.HashSet[string]]::new()
    $alarmDir = Join-Path $Config.paths.state_root 'alarms'
    foreach ($marker in @(Get-ChildItem -Path $alarmDir -Filter '*-open.marker' -File -ErrorAction SilentlyContinue)) {
        try {
            $m = Get-Content -LiteralPath $marker.FullName -Raw | ConvertFrom-Json
            foreach ($k in @($m.keys)) { $null = $suspended.Add($k) }
        }
        catch {}
    }
    return @($Keys | Where-Object { $suspended.Contains($_) })
}

Export-ModuleMember -Function New-EscalationState, Build-EscalationPacket,
    Invoke-Tier2Cycle, Complete-Tier2Outcome, Test-OpenAlarmKeys, Reset-ClearedAlarmKeys,
    Get-EffectiveBatchCap
