# classify.tests.ps1 - whitelist matching, browser policy, residual queue,
# debounce (D2).
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\classify.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\identity.psm1"   # same instance classify uses (signer seam)

function New-Conn {
    param([hashtable]$O = @{})
    $c = @{
        pid = 1234; name = 'proc'; image_path = $null; image_exists = $true
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
    $c = New-Conn @{ name = 'octium'; domain = 'example-dest.test'; attribution_source = 'sni' }
    Assert-True (Test-WhitelistMatch -Entry $ob -Conn $c) 'octium to example-dest.test matches'
    $c = New-Conn @{ name = 'octo browser'; domain = 'app.octobrowser.net'; attribution_source = 'dns-pid' }
    Assert-True (Test-WhitelistMatch -Entry $ob -Conn $c) 'octo browser to octobrowser.net suffix matches'
    $c = New-Conn @{ name = 'chrome'; domain = 'example-dest.test'; attribution_source = 'sni' }
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

    # --- constraint-only entry (DO peers on 7680): used to NEVER match -------
    $do = $wl.entries | Where-Object id -eq 'svchost-delivery-optimization-peer'
    Assert-NotNull $do 'delivery-optimization seed entry present'
    if (-not $env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
    $svcImg = "$($env:SystemRoot)\System32\svchost.exe"
    $c = New-Conn @{ name = 'svchost'; image_path = $svcImg; raddr = '193.57.46.213'; rport = 7680 }
    Assert-True (Test-WhitelistMatch -Entry $do -Conn $c) 'svchost:7680 to arbitrary peer matches'
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'DO peer classified whitelisted'
    # unreadable image (identity 'unknown'): an any-peer grant needs a verified image
    $c = New-Conn @{ name = 'svchost'; raddr = '193.57.46.213'; rport = 7680 }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unknown-identity svchost gets no constraint-only entry'
    # inbound DO peers (they connect to OUR 7680)
    $c = New-Conn @{ name = 'svchost'; image_path = $svcImg; raddr = '193.57.46.213'; rport = 51000; lport = 7680; direction = 'inbound' }
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'inbound DO peer on local 7680 whitelisted'
    $c = New-Conn @{ name = 'svchost'; image_path = $svcImg; raddr = '193.57.46.213'; rport = 51000; lport = 3389; direction = 'inbound' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'inbound svchost on another local port stays residual'
    $c = New-Conn @{ name = 'evil'; raddr = '193.57.46.213'; rport = 7680 }
    Assert-False (Test-WhitelistMatch -Entry $do -Conn $c) 'other process on 7680 not matched'
    $c = New-Conn @{ name = 'svchost'; raddr = '193.57.46.213'; rport = 7681 }
    Assert-False (Test-WhitelistMatch -Entry $do -Conn $c) 'svchost on another port not matched'
    $c = New-Conn @{ name = 'svchost'; raddr = '193.57.46.213'; rport = 7680; direction = 'inbound' }
    Assert-False (Test-WhitelistMatch -Entry $do -Conn $c) 'outbound-default holds for constraint-only entry'
    # an entry pinning only a process (or only a port) must never match all traffic
    $procOnly = [pscustomobject]@{ match = [pscustomobject]@{ processes = @('svchost') } }
    $c = New-Conn @{ name = 'svchost'; raddr = '193.57.46.213'; rport = 443 }
    Assert-False (Test-WhitelistMatch -Entry $procOnly -Conn $c) 'process-only entry matches nothing'
    $portOnly = [pscustomobject]@{ match = [pscustomobject]@{ ports = @(443) } }
    Assert-False (Test-WhitelistMatch -Entry $portOnly -Conn $c) 'port-only entry matches nothing'

    # inert entries (no destination, not process+port) must NOT fail the
    # whole file - an upgrade would otherwise refuse to start on a live
    # whitelist that was valid before (review finding); they load, never
    # match, and are reported once per load as WARN
    $wlSchema = "$PSScriptRoot\..\schemas\whitelist.schema.json"
    $seedRaw = Get-Content "$PSScriptRoot\..\config\whitelist.seed.json" -Raw
    Assert-True (Test-Json -Json $seedRaw -SchemaFile $wlSchema -ErrorAction SilentlyContinue) 'seed whitelist still valid'
    $root2 = New-TestStateRoot
    try {
        $cfg2 = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root2)
        Initialize-StateRoot -Config $cfg2
        $mkEntry = {
            param($id, $match)
            @{ id = $id; match = $match; added_by = 'human'; added_at = '2026-09-25T00:00:00Z'; evidence = 'test' }
        }
        @{ version = 1; entries = @(
                (& $mkEntry 'inbound-rdp-ports-only' @{ local_ports = @(3389); direction = 'inbound' })
                (& $mkEntry 'proc-only' @{ processes = @('svchost') })
                (& $mkEntry 'do-peer' @{ processes = @('svchost'); ports = @(7680) })
                (& $mkEntry 'dom' @{ domains = @('x.example') })
            ) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfg2.paths.whitelist
        $wl2 = Get-Whitelist -Config $cfg2
        Assert-False ($wl2.PSObject.Properties['load_error']) 'previously-valid inert entries do not fail the load'
        Assert-Equal 4 @($wl2.entries).Count 'all entries loaded'
        $log = (Get-ChildItem (Join-Path $root2 'logs') -Filter '*.log' | Get-Content -Raw) -join "`n"
        Assert-True ($log -match "'inbound-rdp-ports-only' is inert") 'ports-only entry reported inert'
        Assert-True ($log -match "'proc-only' is inert") 'process-only entry reported inert'
        Assert-False ($log -match "'do-peer' is inert") 'process+port entry not reported'
        Assert-False ($log -match "'dom' is inert") 'destination entry not reported'
        $c = New-Conn @{ name = 'svchost'; raddr = '100.64.0.21'; lport = 3389; rport = 55000; direction = 'inbound' }
        $inert = $wl2.entries | Where-Object id -eq 'inbound-rdp-ports-only'
        Assert-False (Test-WhitelistMatch -Entry $inert -Conn $c) 'inert entry never matches'
    }
    finally { Remove-TestStateRoot $root2 }

    # --- Get-Classification --------------------------------------------------
    $c = New-Conn @{ name = 'claude'; domain = 'api.anthropic.com'; attribution_source = 'sni' }
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'whitelisted verdict'
    # msedge is pinned by install layout + Microsoft signature (identity.psm1)
    Set-SignerProvider { param($p) 'Microsoft Corporation' }
    if (-not ${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} = 'C:\Program Files (x86)' }
    $edgeImg = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $c = New-Conn @{ name = 'msedge'; image_path = $edgeImg; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'browser-attributed' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'browser with domain'
    $c = New-Conn @{ name = 'msedge'; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unreadable browser image -> no browser credit'
    Set-SignerProvider $null
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
    # transition addresses wrapping 127.x / 169.254.x are routable v6 peers,
    # never local-noise (review finding: would hide real traffic)
    foreach ($ip in '2002:7f00:1::1', '64:ff9b::a9fe:a9fe', '::7f00:1') {
        $c = New-Conn @{ name = 'anything'; raddr = $ip }
        Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) "$ip stays residual"
    }
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
