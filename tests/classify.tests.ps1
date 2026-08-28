# classify.tests.ps1 - whitelist matching, browser policy, residual queue,
# debounce (D2).
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\classify.psm1" -Force

function New-Conn {
    param([hashtable]$O = @{})
    $c = @{
        pid = 1234; name = 'proc'; image_path = 'x'; image_exists = $true
        command_line = ''; laddr = '192.168.1.10'; lport = 50000
        raddr = '1.2.3.4'; rport = 443; state = 'Established'
        direction = 'outbound'; domain = $null; attribution_source = 'none'
    }
    foreach ($k in $O.Keys) { $c[$k] = $O[$k] }
    return $c
}

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg
    $wl = Get-Whitelist -Config $cfg   # seeds from repo seed file

    # --- Test-WhitelistMatch: domain suffixes -------------------------------
    $entry = $wl.entries | Where-Object id -eq 'anthropic-claude-cli'
    Assert-NotNull $entry 'anthropic seed entry present'
    $c = New-Conn @{ name = 'claude'; domain = 'api.anthropic.com'; attribution_source = 'sni' }
    Assert-True (Test-WhitelistMatch -Entry $entry -Conn $c) 'suffix match api.anthropic.com'
    $c = New-Conn @{ name = 'claude'; domain = 'anthropic.com'; attribution_source = 'sni' }
    Assert-True (Test-WhitelistMatch -Entry $entry -Conn $c) 'suffix equals domain'
    $c = New-Conn @{ name = 'claude'; domain = 'notanthropic.com'; attribution_source = 'sni' }
    Assert-False (Test-WhitelistMatch -Entry $entry -Conn $c) 'no substring false-positive'
    $c = New-Conn @{ name = 'evil'; domain = 'api.anthropic.com'; attribution_source = 'sni' }
    Assert-False (Test-WhitelistMatch -Entry $entry -Conn $c) 'process constraint enforced'
    $c = New-Conn @{ name = 'node'; domain = 'API.Anthropic.COM'; attribution_source = 'sni' }
    Assert-True (Test-WhitelistMatch -Entry $entry -Conn $c) 'domain match case-insensitive'

    # --- CIDR entries --------------------------------------------------------
    $tg = $wl.entries | Where-Object id -eq 'telegram'
    $c = New-Conn @{ name = 'telegram'; raddr = '149.154.161.5' }
    Assert-True (Test-WhitelistMatch -Entry $tg -Conn $c) 'telegram CIDR match'
    $c = New-Conn @{ name = 'telegram'; raddr = '8.8.8.8' }
    Assert-False (Test-WhitelistMatch -Entry $tg -Conn $c) 'telegram non-DC IP no match'

    # --- inbound-only entry (iphone RDP seed) --------------------------------
    $ib = $wl.entries | Where-Object id -eq 'tailscale-inbound-rdp-own-iphone'
    $c = New-Conn @{ name = 'svchost'; raddr = '100.64.0.21'; lport = 3389; rport = 55000; direction = 'inbound' }
    Assert-True (Test-WhitelistMatch -Entry $ib -Conn $c) 'own iphone inbound RDP matches'
    $c = New-Conn @{ name = 'svchost'; raddr = '100.64.0.21'; lport = 3389; rport = 55000; direction = 'outbound' }
    Assert-False (Test-WhitelistMatch -Entry $ib -Conn $c) 'same conn outbound does not match'
    $c = New-Conn @{ name = 'svchost'; raddr = '100.99.99.99'; lport = 3389; rport = 55000; direction = 'inbound' }
    Assert-False (Test-WhitelistMatch -Entry $ib -Conn $c) 'other tailnet peer stays unmatched (escalatable)'

    # --- octo-browser seed entry (duty resolution 2026-08-27, alarms
    # 140005/141024) + defender-cloud /32s removed (superseded by domain
    # attribution via microsoft-system) ---------------------------------------
    $ob = $wl.entries | Where-Object id -eq 'octo-browser'
    Assert-NotNull $ob 'octo-browser seed entry present'
    $c = New-Conn @{ name = 'octium'; domain = 'legalize.cc'; attribution_source = 'sni' }
    Assert-True (Test-WhitelistMatch -Entry $ob -Conn $c) 'octium to legalize.cc matches'
    $c = New-Conn @{ name = 'octo browser'; domain = 'app.octobrowser.net'; attribution_source = 'dns-pid' }
    Assert-True (Test-WhitelistMatch -Entry $ob -Conn $c) 'octo browser to octobrowser.net suffix matches'
    $c = New-Conn @{ name = 'chrome'; domain = 'legalize.cc'; attribution_source = 'sni' }
    Assert-False (Test-WhitelistMatch -Entry $ob -Conn $c) 'process constraint holds'
    Assert-Null ($wl.entries | Where-Object id -eq 'mpdefendercoreservice-defender-cloud') 'defender-cloud /32 entry removed from seed'

    # --- direction default: entry without direction never matches inbound ----
    $ms = $wl.entries | Where-Object id -eq 'microsoft-system'
    $c = New-Conn @{ name = 'svchost'; domain = 'update.microsoft.com'; attribution_source = 'dns-pid'; direction = 'inbound' }
    Assert-False (Test-WhitelistMatch -Entry $ms -Conn $c) 'outbound-default entry rejects inbound conn'

    # --- ports constraint (windows365 gateway ip entry) ----------------------
    $w365 = $wl.entries | Where-Object id -eq 'windows365-rdp-gateway-ip'
    $c = New-Conn @{ name = 'msrdc'; raddr = '198.51.100.13'; rport = 3395 }
    Assert-True (Test-WhitelistMatch -Entry $w365 -Conn $c) 'w365 ip+port match'
    $c = New-Conn @{ name = 'msrdc'; raddr = '198.51.100.13'; rport = 443 }
    Assert-False (Test-WhitelistMatch -Entry $w365 -Conn $c) 'w365 wrong port no match'

    # --- Get-Classification --------------------------------------------------
    $c = New-Conn @{ name = 'claude'; domain = 'api.anthropic.com'; attribution_source = 'sni' }
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'whitelisted verdict'
    $c = New-Conn @{ name = 'msedge'; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'browser-attributed' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'browser with domain'
    $c = New-Conn @{ name = 'msedge'; domain = $null; attribution_source = 'none' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'browser raw-IP stays escalatable'
    # operator's antidetect browser: same class as msedge (duty item 2)
    $c = New-Conn @{ name = 'octium'; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'browser-attributed' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'octium attributed = browser class'
    $c = New-Conn @{ name = 'octo browser'; domain = $null; attribution_source = 'none' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'octo browser raw-IP stays escalatable'
    $c = New-Conn @{ name = 'anything'; raddr = '127.0.0.1' }
    Assert-Equal 'local-noise' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'loopback noise'
    $c = New-Conn @{ name = 'anything'; raddr = 'fe80::1' }
    Assert-Equal 'local-noise' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'link-local noise'
    # both-ends-local: remote end is one of THIS host's own addresses
    $hostAddrs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $hostAddrs.Add('192.168.1.10')
    $c = New-Conn @{ name = 'anything'; raddr = '192.168.1.10' }
    Assert-Equal 'local-noise' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg -HostAddresses $hostAddrs) 'own-host remote = both ends local'
    # a DIFFERENT private/tailnet peer is NOT noise (must stay escalatable)
    $c = New-Conn @{ name = 'anything'; raddr = '192.168.1.77' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg -HostAddresses $hostAddrs) 'other LAN peer stays residual'
    $c = New-Conn @{ name = 'unknownproc'; raddr = '203.0.113.7' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unknown proc residual'
    # whitelisted process to unknown destination is NOT whitelisted (F10)
    $c = New-Conn @{ name = 'claude'; raddr = '203.0.113.7'; domain = $null }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'claude to unattributed ip stays residual'

    # --- residual queue + debounce (D2) --------------------------------------
    $queue = @{}
    $t0 = [datetime]::UtcNow
    $c = New-Conn @{ name = 'beacon'; raddr = '203.0.113.7'; rport = 8080 }
    $key = Update-ResidualQueue -Queue $queue -Conn $c -NowUtc $t0
    Assert-Equal 'beacon|203.0.113.7|8080' $key 'residual key format ip'
    $c2 = New-Conn @{ name = 'beacon'; raddr = '203.0.113.7'; rport = 8080; domain = 'evil.example'; attribution_source = 'dns-ip' }
    $key2 = Update-ResidualQueue -Queue $queue -Conn $c2 -NowUtc $t0
    Assert-Equal 'beacon|evil.example|8080' $key2 'residual key format domain'

    # 1 sample, age 10 s -> not escalatable
    $esc = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $t0.AddSeconds(10) -IsSuppressed { $false })
    Assert-Equal 0 $esc.Count 'single fresh sample not escalatable'
    # 2 samples -> escalatable
    $null = Update-ResidualQueue -Queue $queue -Conn $c -NowUtc $t0.AddSeconds(30)
    $esc = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $t0.AddSeconds(31) -IsSuppressed { $false })
    Assert-True ($esc -contains $key) 'two samples escalatable'
    # 1 sample but age 65 s -> escalatable (beacon rule)
    $esc = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $t0.AddSeconds(65) -IsSuppressed { $false })
    Assert-True ($esc -contains $key2) 'old single-sample key escalatable'
    # suppression excludes
    $esc = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $t0.AddSeconds(65) -IsSuppressed { param($k) $k -eq $key })
    Assert-False ($esc -contains $key) 'suppressed key excluded'
    Assert-True ($esc -contains $key2) 'unsuppressed key kept'
    # pending keys excluded
    $queue[$key].pending = $true
    $esc = @(Get-EscalatableKeys -Queue $queue -Config $cfg -NowUtc $t0.AddSeconds(120) -IsSuppressed { $false })
    Assert-False ($esc -contains $key) 'pending key excluded'

    # samples_seen and state history recorded
    Assert-Equal 2 $queue[$key].samples 'sample counter'
    Assert-NotNull $queue[$key].snapshot 'snapshot kept'

    # D2 dedupe: parallel conns with the same key in ONE tick (same NowUtc)
    # count as ONE sample (live smoke run escalated on tick 1 without this)
    $queueD = @{}
    $t1 = [datetime]::UtcNow
    $cd = New-Conn @{ name = 'multi'; raddr = '203.0.113.50'; rport = 443; lport = 50100 }
    $cd2 = New-Conn @{ name = 'multi'; raddr = '203.0.113.50'; rport = 443; lport = 50101 }
    $kd = Update-ResidualQueue -Queue $queueD -Conn $cd -NowUtc $t1
    $null = Update-ResidualQueue -Queue $queueD -Conn $cd2 -NowUtc $t1
    Assert-Equal 1 $queueD[$kd].samples 'same-tick parallel conns = one sample'
    $esc = @(Get-EscalatableKeys -Queue $queueD -Config $cfg -NowUtc $t1.AddSeconds(5) -IsSuppressed { $false })
    Assert-Equal 0 $esc.Count 'not escalatable after a single tick'
    $null = Update-ResidualQueue -Queue $queueD -Conn $cd -NowUtc $t1.AddSeconds(30)
    Assert-Equal 2 $queueD[$kd].samples 'second tick counts'

    # --- whitelist hot-reload: reclassified keys leave the queue -------------
    # Live 2026-08-27: node|api.deepseek.com|443 was whitelisted at 18:36:06Z
    # yet still shipped in escalation packet 20260827-192012-394 (19:20Z) -
    # queue entries were never re-classified after a reload.
    $queueW = @{}
    $t2 = [datetime]::UtcNow
    $cw = New-Conn @{ name = 'claude'; domain = 'api.anthropic.com'; attribution_source = 'sni'; raddr = '203.0.113.60' }
    $cr = New-Conn @{ name = 'unknownproc'; raddr = '203.0.113.61' }
    $kw = Update-ResidualQueue -Queue $queueW -Conn $cw -NowUtc $t2   # imagine queued before the wl edit
    $kr = Update-ResidualQueue -Queue $queueW -Conn $cr -NowUtc $t2
    $queueW[$kw].pending = $true   # even alarm-suspended keys must leave once whitelisted
    $removed = @(Remove-ReclassifiedQueueKeys -Queue $queueW -Whitelist $wl -Config $cfg)
    Assert-Equal 1 $removed.Count 'one key evicted on reload'
    Assert-Equal $kw $removed[0] 'whitelisted key evicted'
    Assert-False $queueW.ContainsKey($kw) 'evicted key gone from queue'
    Assert-True $queueW.ContainsKey($kr) 'still-residual key kept'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
