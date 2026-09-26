# netwatch.ps1 - Tier-1 entry point: collector + orchestrator main loop
# (ARCHITECTURE 3.1). Single instance via mutex (F18); every tick is wrapped
# so one bad cycle never kills the monitor.
# Test hooks: -NoMutex, -MaxTicks, -TickDelaySec (prod default = config
# sample_interval_sec), -ConfigPath.

#Requires -Version 7.6
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\..\config\netwatch.config.json'),
    [switch]$Once,
    [int]$MaxTicks = 0,
    [int]$TickDelaySec = -1,
    [switch]$NoMutex
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($m in 'state', 'netutil', 'sampling', 'classify', 'dnsetw', 'snicapture', 'enrich', 'escalate', 'toast', 'dolog', 'sysmon') {
    Import-Module (Join-Path $PSScriptRoot "modules\$m.psm1") -Force
}

# --- single instance (F18) ---------------------------------------------------
$mutex = $null
if (-not $NoMutex) {
    $mutex = [System.Threading.Mutex]::new($false, 'Global\netwatch-tier1')
    if (-not $mutex.WaitOne(0)) {
        Write-Host 'netwatch already running (mutex held) - exiting'
        exit 0
    }
}

try {
    # --- init ----------------------------------------------------------------
    $cfg = Get-NetwatchConfig -Path $ConfigPath
    Initialize-StateRoot -Config $cfg
    $whitelist = Get-Whitelist -Config $cfg
    $wlMtime = (Get-Item -LiteralPath $cfg.paths.whitelist -ErrorAction SilentlyContinue)?.LastWriteTimeUtc
    Update-OwnIp -Config $cfg

    $dnsCaches = New-DnsCaches
    $sniCaches = @{ sni = @{} }
    $sniState  = New-SniState
    Start-SniCapture -Config $cfg -State $sniState
    $health = @{
        sni_capture = $sniState.health
        dns_etw     = (Test-DnsEtwAvailable)
        sysmon      = (Test-SysmonAvailable)     # optional: fills the 30-s poll gap
    }
    if ($health.dns_etw -ne 'ok') {
        $null = Send-NetwatchToast -Config $cfg -Title 'netwatch: DNS attribution off' `
            -Message 'DNS-Client ETW channel not enabled. Run install/enable-etw.ps1 (admin) to restore DNS attribution.'
    }

    $pidCache  = @{}
    $queue     = @{}          # residual queue
    $escState  = New-EscalationState
    $activeLogged = @{}       # conn-log dedup: key -> last-seen tick index
    $lastTick  = [datetime]::MinValue
    $lastOwnIp = [datetime]::UtcNow
    $lastEgressChange = [datetime]::MinValue   # own-ip redetect fires per change, not per hour
    $wlErrorToasted = $false                   # F20: one toast per bad-load episode
    $lastHkDay = (Get-Date).Date
    $floodToasted = $false
    $tick = 0
    $delaySec = if ($TickDelaySec -ge 0) { $TickDelaySec } else { $cfg.sample_interval_sec }
    if ($Once) { $MaxTicks = 1 }

    Write-OpLog -Config $cfg -Level INFO -Message "netwatch started (pid $PID, sni=$($health.sni_capture), dns_etw=$($health.dns_etw), sysmon=$($health.sysmon))"

    # --- main loop -----------------------------------------------------------
    while ($true) {
        $tick++
        $now = [datetime]::UtcNow
        try {
            # F17: sleep/resume gap - full rebaseline (samples AND first_seen,
            # otherwise the age>=60s rule would instantly escalate stale keys)
            if ($lastTick -ne [datetime]::MinValue -and
                ($now - $lastTick).TotalSeconds -gt 3 * $cfg.sample_interval_sec) {
                foreach ($k in @($queue.Keys)) {
                    $queue[$k].samples = 0
                    $queue[$k].first_seen = $now
                }
                Write-OpLog -Config $cfg -Level INFO -Message "tick gap $([int]($now - $lastTick).TotalSeconds)s (sleep/resume?) - counters rebaselined"
            }

            # whitelist hot-reload on file change (F20-safe inside Get-Whitelist)
            $mt = (Get-Item -LiteralPath $cfg.paths.whitelist -ErrorAction SilentlyContinue)?.LastWriteTimeUtc
            if ($mt -and $mt -ne $wlMtime) {
                $whitelist = Get-Whitelist -Config $cfg
                $wlMtime = $mt
                Write-OpLog -Config $cfg -Level INFO -Message 'whitelist reloaded (file changed)'
                # F20 accountability toast (one per bad-load episode)
                if ($whitelist.PSObject.Properties['load_error'] -and $whitelist.load_error) {
                    if (-not $wlErrorToasted) {
                        $wlErrorToasted = $true
                        $null = Send-NetwatchToast -Config $cfg -Urgent -Title 'netwatch: whitelist load failed' `
                            -Message "Running on the last-good copy: $($whitelist.load_error)"
                    }
                }
                else { $wlErrorToasted = $false }
                # re-classify queued keys against the new whitelist - a key the
                # operator just whitelisted must not keep escalating (2026-08-27
                # repeat-alarm loop)
                $evicted = @(Remove-ReclassifiedQueueKeys -Queue $queue -Whitelist $whitelist -Config $cfg -HostAddresses (Get-HostAddresses))
                if ($evicted.Count) {
                    Write-OpLog -Config $cfg -Level INFO -Message "residual queue: evicted $($evicted.Count) reclassified key(s): $($evicted -join ', ')"
                }
            }

            # 1-3. sample + drain attribution sources
            $listen = Get-ListenPorts
            $sample = @(Get-ConnectionSample -PidCache $pidCache -ListenPorts $listen)
            # PID-reuse guard: drop cache entries for PIDs with no live conns
            Sync-PidCache -PidCache $pidCache -ActivePids @($sample | ForEach-Object pid)
            # Sysmon event 3: connections that opened AND closed between two
            # polls exist only here (after Sync-PidCache - event conns carry
            # their own image path and must not keep dead PIDs cached)
            $health.sysmon = Test-SysmonAvailable
            if ($health.sysmon -eq 'ok') {
                $sample = @(Merge-SysmonConnections -Sample $sample -Events @(Read-SysmonConnections -Config $cfg))
            }
            $hostAddrs = Get-HostAddresses

            # F5: health re-probed every tick (runtime failures AND operator
            # enabling the channel are both picked up without a restart)
            $health.dns_etw = Test-DnsEtwAvailable
            if ($health.dns_etw -eq 'ok') {
                # @() coercion: an empty drain unrolls to $null otherwise
                $dnsEvents = @(Read-DnsEvents -Config $cfg)
                Update-DnsCaches -Caches $dnsCaches -Events $dnsEvents -NowUtc $now
            }
            # OS resolver cache: ambient raddr->domain that works even when SNI
            # is blind (VPN data-channel offload) and ETW missed the lookup
            Update-DnsClientCache -Caches $dnsCaches -NowUtc $now
            $health.sni_capture = Test-SniHealth -Config $cfg -State $sniState -NowUtc $now
            # F4 accountability toast: one per degraded episode (the
            # degraded_toasted latch existed since design but was never wired)
            if ($health.sni_capture -eq 'degraded' -and -not $sniState.degraded_toasted) {
                $sniState.degraded_toasted = $true
                $null = Send-NetwatchToast -Config $cfg -Title 'netwatch: SNI capture degraded' `
                    -Message 'Capture child dead or blind; attribution continues via DNS sources. See op-log.'
            }
            elseif ($health.sni_capture -eq 'ok' -and $sniState.degraded_toasted) {
                $sniState.degraded_toasted = $false
            }
            Read-SniLines -State $sniState -Caches $sniCaches -NowUtc $now
            # a recent egress rebind rides into the packet as context (tier2
            # must not read post-switch address rotation as evidence)
            if ($sniState.last_change -and ($now - $sniState.last_change.at).TotalHours -lt 1) {
                $health.egress_note = 'egress interface set changed {0:hh\:mm\:ss} ago: [{1}] -> [{2}]' -f `
                    ($now - $sniState.last_change.at),
                    ($sniState.last_change.old -join ', '), ($sniState.last_change.new -join ', ')
            }
            else { $health.Remove('egress_note') }
            # a channel switch changes the public IP NOW, not within the hourly
            # timer - stale own-ip either refuses reputation for a foreign
            # address as 'own' or fails to exclude the current one (task 3)
            if ($sniState.last_change -and $sniState.last_change.at -gt $lastEgressChange) {
                $lastEgressChange = $sniState.last_change.at
                Update-OwnIp -Config $cfg
                $lastOwnIp = $now
                Write-OpLog -Config $cfg -Level INFO -Message 'egress change detected - own-ip redetection triggered'
            }

            # F19: alarm keys whose open-marker the human deleted become
            # escalatable again
            $null = Reset-ClearedAlarmKeys -Config $cfg -Queue $queue

            # 4-6. attribute, classify, log/queue
            $seenKeys = @{}
            foreach ($c in $sample) {
                $att = Resolve-SniAttribution -Caches $sniCaches -Conn $c
                if (-not $att) { $att = Resolve-DnsAttribution -Caches $dnsCaches -Conn $c }
                if ($att.source -eq 'none') {
                    # last resort for svchost/dosvc:80 raw-IP: the DO journal's
                    # CacheHost records (MCC nodes rotate - DO-LOG-ATTRIBUTION)
                    $dlAtt = Resolve-DoLogAttribution -Conn $c
                    if ($dlAtt) { $att = $dlAtt }
                }
                $c.attribution_source = $att.source
                $c.domain = $att.domain

                $class = Get-Classification -Whitelist $whitelist -Conn $c -Config $cfg -HostAddresses $hostAddrs
                $key = Get-ResidualKey -Conn $c
                $seenKeys[$key] = $true
                switch ($class) {
                    'local-noise' { }   # trace-level only; not persisted
                    { $_ -in 'whitelisted', 'browser-attributed' } {
                        if (-not $activeLogged.ContainsKey($key)) {
                            Write-ConnLog -Config $cfg -Record @{
                                ts_utc = $now.ToString('o'); key = $key; verdict = $class
                                process = $c.name; pid = $c.pid; raddr = $c.raddr; rport = $c.rport
                                domain = $c.domain; attribution = $c.attribution_source
                                direction = $c.direction
                            }
                        }
                        $activeLogged[$key] = $tick
                    }
                    'residual' {
                        $null = Update-ResidualQueue -Queue $queue -Conn $c -NowUtc $now
                        # immediate triggers: F14 deleted image, F15 unclassified
                        # inbound. Sticky on the queue entry - a short-lived
                        # trigger must not be forgotten next tick.
                        if ((Test-ImageGone -Conn $c) -or $c.direction -eq 'inbound') {
                            $queue[$key].immediate = $true
                        }
                    }
                }
            }
            # conn-log dedup: forget keys absent for a full tick (re-log later)
            foreach ($k in @($activeLogged.Keys)) {
                if (-not $seenKeys.ContainsKey($k) -and $activeLogged[$k] -lt $tick) { $activeLogged.Remove($k) }
            }
            # drop stale residuals never escalated (suppressed/vanished) after 2h
            foreach ($k in @($queue.Keys)) {
                if (-not $queue[$k].pending -and ($now - $queue[$k].last_seen).TotalHours -gt 2) { $queue.Remove($k) }
            }

            # 7. debounce -> escalatable minus suppressed minus open-alarm keys
            $escalatable = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $now `
                    -IsSuppressed { param($k) Test-Suppressed -Config $cfg -Key $k })
            $suspended = @(Test-OpenAlarmKeys -Config $cfg -Keys $escalatable)
            $escalatable = @($escalatable | Where-Object { $_ -notin $suspended })
            # sticky immediate flags among what is actually escalatable (F14/F15)
            $immediate = [bool]@($escalatable | Where-Object { $queue[$_].immediate })

            # 8. escalation decision
            if ($escalatable.Count -gt 0) {
                $blind = ($health.sni_capture -ne 'ok' -and $health.dns_etw -ne 'ok')
                if ($blind -and $escalatable.Count -gt 3 * $cfg.tier2.batch_cap) {
                    # F6 flood guard: attribution lost, do not spam Tier 2
                    if (-not $floodToasted) {
                        $null = Send-NetwatchToast -Config $cfg -Urgent -Title 'netwatch BLIND' `
                            -Message "Attribution lost (SNI+DNS down), $($escalatable.Count) unclassified conns. Human decision required."
                        $floodToasted = $true
                    }
                    Write-OpLog -Config $cfg -Level ERROR -Message "flood guard active: $($escalatable.Count) residuals while blind (F6)"
                }
                elseif ($now -ge $escState.next_allowed -and
                       ($immediate -or ($now - $escState.last_tier2).TotalMinutes -ge $cfg.tier2.min_interval_min)) {
                    # enrich only what ships: same oldest-first order the packet
                    # builder uses, so the shipped batch is the enriched batch
                    $exclusions = Get-OwnIpExclusions -Config $cfg
                    $shipOrder = @($escalatable | Sort-Object { $queue[$_].first_seen })
                    foreach ($k in ($shipOrder | Select-Object -First (Get-EffectiveBatchCap -Config $cfg))) {
                        $q = $queue[$k]
                        if (-not $q.enriched) {
                            $ip = $q.snapshot.raddr
                            if (-not (Test-ExcludedFromLookup -Ip $ip -Exclusions $exclusions)) {
                                $q.enriched = Get-CymruAsn -Ip $ip
                            }
                        }
                    }
                    $packet = Build-EscalationPacket -Keys $escalatable -Queue $queue -Config $cfg `
                        -Health $health -NowUtc $now
                    Write-OpLog -Config $cfg -Level INFO -Message "escalating $($packet.connections.Count) key(s) to tier2 (immediate=$immediate)"
                    $escState.last_tier2 = $now
                    $result = Invoke-Tier2Cycle -Packet $packet -Config $cfg -ConfigPath $ConfigPath
                    Complete-Tier2Outcome -Result $result -Packet $packet -Config $cfg -Queue $queue -EscState $escState
                }
            }

            # 9. housekeeping: daily retention + hourly own-IP redetect (F8)
            if ((Get-Date).Date -ne $lastHkDay) {
                Invoke-Housekeeping -Config $cfg
                $lastHkDay = (Get-Date).Date
            }
            if (($now - $lastOwnIp).TotalMinutes -ge $cfg.own_ip.redetect_interval_min) {
                Update-OwnIp -Config $cfg
                $lastOwnIp = $now
            }
            Write-OpLog -Config $cfg -Level TRACE -Message "tick $tick done: sample=$($sample.Count) residual=$($queue.Count) escalatable=$($escalatable.Count)"
            # F17 gap measures from tick END: in-tick work (a 1-3 min Tier-2
            # run) must not look like sleep/resume (live smoke run finding)
            $lastTick = [datetime]::UtcNow
        }
        catch {
            Write-OpLog -Config $cfg -Level ERROR -Message "tick $tick failed: $($_.Exception.Message) @ $($_.ScriptStackTrace -split "`n" | Select-Object -First 1)"
        }

        if ($MaxTicks -gt 0 -and $tick -ge $MaxTicks) { break }
        Start-Sleep -Seconds $delaySec
    }

    Stop-SniCapture -State $sniState
    Write-OpLog -Config $cfg -Level INFO -Message "netwatch stopped after $tick tick(s)"
}
finally {
    if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
}
