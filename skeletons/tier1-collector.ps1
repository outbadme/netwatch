# tier1-collector.ps1 — netwatch Tier-1 main loop skeleton (pwsh 7 only).
# Structure mirrors ARCHITECTURE.md §3.1; implementer fills TODO bodies,
# preferably by extracting them into the modules/ listed in ARCHITECTURE §2.
# Registered as a logon Scheduled Task (interactive user, highest privileges).

#Requires -Version 7
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- single instance (F18) ---------------------------------------------------
$mutex = [System.Threading.Mutex]::new($false, 'Global\netwatch-tier1')
if (-not $mutex.WaitOne(0)) { Write-Host 'netwatch already running'; exit 0 }

# --- init --------------------------------------------------------------------
$cfgPath   = "$PSScriptRoot\..\config\netwatch.config.json"
$cfg       = Get-Content $cfgPath -Raw | ConvertFrom-Json
$stateRoot = [Environment]::ExpandEnvironmentVariables($cfg.paths.state_root)
$claudeExe = [Environment]::ExpandEnvironmentVariables($cfg.tier2.claude_exe)
$whitelist = $null   # TODO state.psm1: load + schema-validate; keep last-good on failure (F20)
$caches = @{
    dns_ip     = @{}   # ip -> @{domains=[]; expires}
    dns_pidip  = @{}   # "pid|ip" -> @{domain; expires}
    sni        = @{}   # "ip:port" -> @{sni; expires}
    pid_image  = @{}   # pid -> @{name; path; cmdline; exists}
    residual   = @{}   # key -> @{first_seen; samples; conn-snapshot; enriched}
    suppression= @{}   # TODO load state\suppression.json (TTL 24h entries)
}
# TODO enrich.psm1: own-IP init — Resolve-DnsName myip.opendns.com -Server resolver1.opendns.com
#   exclusion set = detected + last-known + $cfg.own_ip.recorded_static (fail-closed, F7)
# TODO dnsetw.psm1: startup probe of Microsoft-Windows-DNS-Client/Operational (F5)
# TODO snicapture.psm1: start tshark child:
#   tshark -l -i <iface> -f "tcp port 443 or tcp port 8443" -Y "tls.handshake.type==1" `
#     -T fields -e ip.dst -e ipv6.dst -e tcp.dstport -e tls.handshake.extensions_server_name
#   supervise with backoff per F4
$health = @{ sni_capture = 'ok'; dns_etw = 'ok' }
$lastTier2 = [datetime]::MinValue

# --- main loop ---------------------------------------------------------------
while ($true) {
    $now = [datetime]::UtcNow
    try {
        # 1. sample
        $conns = Get-NetTCPConnection -State Established,SynSent -ErrorAction SilentlyContinue
        # TODO sampling.psm1: + Listen inventory; PID -> image/cmdline via CIM (cache pid_image);
        #   direction detection (inbound = remote initiated: heuristic via Listen table match)

        # 2. drain ETW DNS (bookmarked)      -> caches.dns_*        (dnsetw.psm1)
        # 3. drain tshark stdout             -> caches.sni          (snicapture.psm1)

        foreach ($c in $conns) {
            # 4. attribute: sni(ip:port) ?? dns_pidip ?? dns_ip ?? none   (classify.psm1)
            # 5. classify: whitelist match (domain_suffixes -> domains -> cidrs;
            #    process/ports/local_ports/direction constraints);
            #    browser policy: msedge/msedgewebview2 + attributed domain => clean-log;
            #    matched => append conn-YYYYMMDD.jsonl once per key lifetime
            # 6. residual: key = "$procname|$($domain ?? $ip)|$rport";
            #    skip if suppressed/pending; update first_seen/samples
        }

        # debounce -> escalatable set (min_samples=2 OR age>=60s)
        $escalatable = @() # TODO classify.psm1
        # 7. enrich escalatable with Cymru ASN (skip own/private/CGNAT ips)   (enrich.psm1)

        # 8. escalation decision
        $immediate = $false # TODO: unclassified inbound (F15) or image_exists=false (F14)
        $blind = ($health.sni_capture -ne 'ok' -and $health.dns_etw -ne 'ok')
        if ($escalatable.Count -gt 0 -and -not (Test-OpenAlarmForKeys $escalatable)) {   # F19
            if ($blind -and $escalatable.Count -gt 3 * $cfg.tier2.batch_cap) {
                # F6 flood guard: do not invoke Tier 2, toast "netwatch blind"
            }
            elseif ($immediate -or ($now - $lastTier2).TotalMinutes -ge $cfg.tier2.min_interval_min) {
                $packet = $null # TODO escalate.psm1: build packet (schema escalation-packet),
                                #   include collector_health + machine_notes from config
                $rc = & pwsh -File "$PSScriptRoot\invoke-tier2.ps1" `
                        -PacketPath $packet -ConfigPath $cfgPath
                $lastTier2 = $now
                switch ($LASTEXITCODE) {
                    0 { # parse verdict.json: ALARM -> launch-tier3; CLEAN -> toast +
                        # suppression entries (TTL 24h) + append proposals.jsonl (D1)
                    }
                    2 { # timeout: Tier 3 immediately, reason tier2_timeout (F1)
                        & pwsh -File "$PSScriptRoot\launch-tier3.ps1" -Reason tier2_timeout `
                            -AlarmFile $packet -ClaudeExe $claudeExe -StateRoot $stateRoot
                    }
                    3 { # launch failure: toast + backoff (F3)
                    }
                    4 { # bad output: retry once this cycle, then Tier 3 (F2/F24)
                    }
                }
            }
        }

        # 9. housekeeping: first tick after local midnight -> retention (D5),
        #    quota ledger reset; hourly -> own-IP re-detect (F8)
    }
    catch {
        # op-log ERROR; never let one cycle kill the collector
    }
    Start-Sleep -Seconds $cfg.sample_interval_sec
}
