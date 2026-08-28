# snicapture.psm1 - tshark child-process supervisor + domain cache fed by TLS
# ClientHello SNI (443/8443) and plaintext HTTP Host headers (http_ports,
# default 80 - CRL/OCSP class). tshark output contract (-T fields,
# tab-separated, http.host LAST so legacy 4-field lines stay parseable):
#   ip.dst  ipv6.dst  tcp.dstport  tls.handshake.extensions_server_name  http.host
# Capture is bound explicitly to interfaces (config sni.interfaces, else every
# Up adapter with a routable address) - see Get-SniInterface for why omitting
# -i silently produces an empty capture.
# Supervision per F4: restart with backoff, degraded after N restarts;
# missing tshark/Npcap => 'unavailable' (deploy item), never a crash.

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'state.psm1')

$script:CacheTtlHours = 2

function New-SniState {
    return @{
        proc        = $null
        queue       = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        err_queue   = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        event_sub   = $null
        event_sub_err = $null
        health      = 'unavailable'
        restarts    = 0
        backoff_idx = 0
        waiting_restart = $false
        next_start  = [datetime]::MinValue
        degraded_toasted = $false
        lines_seen  = 0          # 'ok' only means the child is alive; this is the proof it captures
        started_at  = [datetime]::MinValue
        last_line_at = [datetime]::MinValue   # stamped by Read-SniLines; blindness = age of newest evidence
        blind_warned = $false
        interfaces  = @()        # the set the running child is bound to
        iface_candidate = $null  # differing set awaiting the settle debounce
        iface_candidate_since = [datetime]::MinValue
        last_change = $null      # @{ at; old; new } of the latest rebind (packet notes)
    }
}

function Get-SniInterface {
    # Which adapters to capture on. WITHOUT -i tshark binds to the FIRST
    # adapter it enumerates, which on a host with WAN-miniport pseudo-adapters
    # ('Local Area Connection* N') carries no traffic at all: the child then
    # runs forever, reports healthy, and yields zero SNI - attribution silently
    # degrades to /32 whitelists that break as soon as the peer rotates IPs.
    # Configured names win; otherwise every Up adapter holding a routable
    # unicast address (skips loopback, APIPA and the hidden miniports).
    param([Parameter(Mandatory)] $Config)

    $configured = @()
    $sni = $Config.sni
    $hasKey = if ($sni -is [hashtable]) { $sni.ContainsKey('interfaces') }
              else { [bool]($sni.PSObject.Properties.Name -contains 'interfaces') }
    if ($hasKey) { $configured = @($sni.interfaces | Where-Object { $_ }) }
    if ($configured.Count) { return $configured }

    try {
        return @(Get-NetAdapter -ErrorAction Stop |
            Where-Object { $_.Status -eq 'Up' } |
            Where-Object {
                @(Get-NetIPAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue |
                    Where-Object { $_.AddressState -eq 'Preferred' -and
                                   $_.IPAddress -notmatch '^(127\.|::1$|169\.254\.)' }).Count -gt 0
            } | Select-Object -ExpandProperty Name)
    }
    catch { return @() }
}

function Start-SniCapture {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [hashtable]$State
    )
    $exe = $Config.sni.tshark_exe
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        $State.health = 'unavailable'
        Write-OpLog -Config $Config -Level WARN -Message "tshark not found at $exe - SNI capture unavailable (deploy item)"
        return
    }
    $ifaces = @(Get-SniInterface -Config $Config)
    $State.interfaces = @($ifaces)
    if (-not $ifaces.Count) {
        $State.health = 'unavailable'
        Write-OpLog -Config $Config -Level WARN -Message 'no Up adapter with a routable address - SNI capture unavailable'
        return
    }
    try {
        # http_ports (default 80): plaintext HTTP joins the capture so the
        # Host header can attribute CRL/OCSP-class traffic where no TLS
        # ClientHello exists (live alarm 20260827-143918)
        $httpPorts = @(80)
        if ($Config.sni.PSObject.Properties['http_ports']) { $httpPorts = @($Config.sni.http_ports) }
        $allPorts = @($Config.sni.capture_ports) + $httpPorts
        $portFilter = ($allPorts | Select-Object -Unique | ForEach-Object { "tcp port $_" }) -join ' or '
        $ifArgs = @(); foreach ($n in $ifaces) { $ifArgs += @('-i', $n) }
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $exe
        foreach ($a in @(
                $ifArgs,
                '-l', '-n',
                '-f', $portFilter,
                '-Y', 'tls.handshake.type==1 or http.request',
                '-T', 'fields',
                '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', 'tcp.dstport',
                '-e', 'tls.handshake.extensions_server_name',
                '-e', 'http.host'    # LAST: legacy 4-field lines must keep parsing
            ) | ForEach-Object { $_ }) { $psi.ArgumentList.Add($a) }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $proc = [System.Diagnostics.Process]::new()
        $proc.StartInfo = $psi
        $null = $proc.Start()
        # async line pump into the thread-safe queue
        $State.event_sub = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived `
            -MessageData $State.queue -Action {
                if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) }
            }
        # stderr MUST be drained too: an undrained redirected pipe fills its
        # ~4KB buffer and blocks tshark alive-but-frozen, invisible to the
        # HasExited supervisor (review finding).
        $State.event_sub_err = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived `
            -MessageData $State.err_queue -Action {
                if ($null -ne $EventArgs.Data) { $Event.MessageData.Enqueue($EventArgs.Data) }
            }
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()
        $State.proc = $proc
        $State.health = 'ok'
        $State.started_at = [datetime]::UtcNow      # blindness is measured per child
        $State.lines_seen = 0
        $State.last_line_at = [datetime]::MinValue
        $State.blind_warned = $false
        Write-OpLog -Config $Config -Level INFO -Message "sni capture started (pid $($proc.Id), filter '$portFilter', interfaces: $($ifaces -join ', '))"
    }
    catch {
        $State.health = 'unavailable'
        Write-OpLog -Config $Config -Level ERROR -Message "sni capture start failed: $($_.Exception.Message)"
    }
}

function Stop-SniCapture {
    param([Parameter(Mandatory)] [hashtable]$State)
    foreach ($subKey in 'event_sub', 'event_sub_err') {
        if ($State[$subKey]) {
            Unregister-Event -SourceIdentifier $State[$subKey].Name -ErrorAction SilentlyContinue
            $State[$subKey] = $null
        }
    }
    if ($State.proc -and -not $State.proc.HasExited) {
        try { $State.proc.Kill($true) } catch {}
    }
    $State.proc = $null
}

function ConvertFrom-TsharkLine {
    # One TSV line -> @{ ip; port; domain; source } or $null (incomplete lines
    # skipped). Field 4 (http.host) is OPTIONAL: legacy 4-field lines (TLS
    # only) must keep parsing, so the count check stays -lt 4. SNI wins over
    # the Host header when both exist. NB: lines whose tcp.dstport is empty
    # (TCP reassembly artefact) are dropped here - long-standing behavior.
    param([AllowEmptyString()] [string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $f = $Line.Split("`t")
    if ($f.Count -lt 4) { return $null }
    $ip = if ($f[0]) { $f[0].Trim() } else { $f[1].Trim() }
    $sni = $f[3].Trim()
    $hostHdr = if ($f.Count -ge 5) { $f[4].Trim() } else { '' }
    $port = 0
    if (-not $ip -or -not [int]::TryParse($f[2].Trim(), [ref]$port)) { return $null }
    if ($sni) {
        # some captures report multiple SNIs comma-joined; first one wins
        return @{ ip = $ip; port = $port; source = 'sni'
                  domain = $sni.Split(',')[0].ToLowerInvariant().TrimEnd('.') }
    }
    if ($hostHdr) {
        # Host header may carry an explicit :port; an IP-literal host adds no
        # attribution value over raddr itself
        $h = $hostHdr.Split(',')[0].Split(':')[0].ToLowerInvariant().TrimEnd('.')
        $addr = $null
        if (-not $h -or [System.Net.IPAddress]::TryParse($h, [ref]$addr)) { return $null }
        return @{ ip = $ip; port = $port; source = 'http-host'; domain = $h }
    }
    return $null
}

function Update-SniCache {
    param(
        [Parameter(Mandatory)] [hashtable]$Caches,
        $Entry,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    if ($null -eq $Entry) { return }
    $Caches.sni["$($Entry.ip):$($Entry.port)"] = @{
        domain  = $Entry.domain
        source  = $Entry.source        # 'sni' | 'http-host' (Host header is client-forgeable, weaker)
        expires = $NowUtc.AddHours($script:CacheTtlHours)
    }
}

function Read-SniLines {
    # Drains the queue into the cache; prunes expired entries.
    param(
        [Parameter(Mandatory)] [hashtable]$State,
        [Parameter(Mandatory)] [hashtable]$Caches,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    $line = ''
    $drained = 0
    while ($State.queue.TryDequeue([ref]$line)) {
        $State.lines_seen++
        $drained++
        Update-SniCache -Caches $Caches -Entry (ConvertFrom-TsharkLine -Line $line) -NowUtc $NowUtc
    }
    if ($drained -gt 0) { $State.last_line_at = $NowUtc }
    foreach ($k in @($Caches.sni.Keys)) {
        if ($Caches.sni[$k].expires -le $NowUtc) { $Caches.sni.Remove($k) }
    }
}

function Test-SameInterfaceSet {
    # order-insensitive set equality; Compare-Object rejects empty arrays
    param([array]$A, [array]$B)
    $a = @($A | Sort-Object -Unique)
    $b = @($B | Sort-Object -Unique)
    if ($a.Count -ne $b.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
    return $true
}

function Test-SniHealth {
    # Supervisor tick (F4): dead child -> restart after backoff; after
    # max_restarts_before_degraded the health becomes 'degraded' (ETW-only
    # attribution continues; packets carry the flag).
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [hashtable]$State,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    if ($State.health -eq 'unavailable') { return $State.health }
    if ($State.proc -and -not $State.proc.HasExited) {
        # Egress re-detection (2026-08-28): the interface set was computed ONCE
        # at Start, so a VPN coming up later left the child on stale adapters
        # (measured 27.08: the DCO adapter carried 220 of 239 TLS/443 packets
        # while the child sat on Ethernet). Compare as SETS, debounce adapter
        # flapping via interface_settle_sec, and rebind WITHOUT touching
        # `restarts` - that counter means a crashing child, not an intentional
        # rebind, and must not drive the capture into 'degraded'.
        $recheck = $true
        if ($Config.sni.PSObject.Properties['interface_recheck']) { $recheck = [bool]$Config.sni.interface_recheck }
        if ($recheck) {
            $settle = 60
            if ($Config.sni.PSObject.Properties['interface_settle_sec']) { $settle = $Config.sni.interface_settle_sec }
            $current = @(Get-SniInterface -Config $Config)
            if (-not $current.Count -or (Test-SameInterfaceSet $State.interfaces $current)) {
                $State.iface_candidate = $null    # unchanged (or nothing up: keep what we have)
            }
            else {
                if (-not ($State.iface_candidate -and (Test-SameInterfaceSet $State.iface_candidate $current))) {
                    $State.iface_candidate = @($current)
                    $State.iface_candidate_since = $NowUtc
                }
                elseif (($NowUtc - $State.iface_candidate_since).TotalSeconds -ge $settle) {
                    $old = @($State.interfaces)
                    Write-OpLog -Config $Config -Level INFO -Message "egress interface set changed: [$($old -join ', ')] -> [$($current -join ', ')] - rebinding capture"
                    Stop-SniCapture -State $State
                    Start-SniCapture -Config $Config -State $State
                    $State.iface_candidate = $null
                    $State.last_change = @{ at = $NowUtc; old = $old; new = @($current) }
                    return $State.health
                }
            }
        }
        # A live child is NOT proof of capture: bound to an adapter that carries
        # no traffic it runs forever, healthy and silent, and attribution stays
        # empty without anyone noticing. Treat a long-running child that has
        # produced nothing as degraded - same flag the packet already carries.
        $blindAfter = 600
        if ($Config.sni.PSObject.Properties['blind_after_sec']) { $blindAfter = $Config.sni.blind_after_sec }
        if ($blindAfter -gt 0 -and $State.started_at -ne [datetime]::MinValue) {
            # blindness = age of the NEWEST evidence (child start or last line),
            # so a capture that produced lines and then went silent (VPN came
            # up mid-day, offload hides TLS) is caught too - not only the
            # never-produced-anything case
            $lastEvidence = if ($State.last_line_at -gt $State.started_at) { $State.last_line_at } else { $State.started_at }
            if ($State.health -eq 'ok' -and $NowUtc -ge $lastEvidence.AddSeconds($blindAfter)) {
                $State.health = 'degraded'
                $State.blind_warned = $true
                Write-OpLog -Config $Config -Level WARN -Message "sni capture alive but no lines for ${blindAfter}s - attribution is blind; check sni.interfaces / VPN offload"
            }
            elseif ($State.blind_warned -and $NowUtc -lt $lastEvidence.AddSeconds($blindAfter)) {
                $State.health = 'ok'                  # capture recovered on its own
                $State.blind_warned = $false
                Write-OpLog -Config $Config -Level INFO -Message 'sni capture producing lines again'
            }
        }
        return $State.health
    }

    # child is dead
    if ($State.restarts -ge $Config.sni.max_restarts_before_degraded) {
        $State.health = 'degraded'
        return $State.health
    }
    if (-not $State.waiting_restart) {
        # F4: the backoff delay comes BEFORE the restart attempt (5/30/300 s)
        $backoffs = @($Config.sni.restart_backoff_sec)
        $delay = $backoffs[[math]::Min($State.backoff_idx, $backoffs.Count - 1)]
        $State.next_start = $NowUtc.AddSeconds($delay)
        $State.backoff_idx++
        $State.waiting_restart = $true
        Stop-SniCapture -State $State
        $lastErr = ''
        while ($State.err_queue.TryDequeue([ref]$lastErr)) {}   # keep last stderr line
        Write-OpLog -Config $Config -Level WARN -Message "tshark child died; restart #$($State.restarts + 1) in ${delay}s $(if ($lastErr) { "(stderr: $lastErr)" })"
        return $State.health
    }
    if ($NowUtc -lt $State.next_start) { return $State.health }   # waiting out backoff

    $State.waiting_restart = $false
    $State.restarts++
    Start-SniCapture -Config $Config -State $State
    return $State.health
}

function Resolve-SniAttribution {
    # ip:port cache hit -> @{source='sni'|'http-host'; domain}; else $null.
    param(
        [Parameter(Mandatory)] [hashtable]$Caches,
        [Parameter(Mandatory)] $Conn
    )
    $key = "$($Conn.raddr):$($Conn.rport)"
    if ($Caches.sni.ContainsKey($key)) {
        $hit = $Caches.sni[$key]
        return @{ source = $hit.source; domain = $hit.domain }
    }
    return $null
}

Export-ModuleMember -Function New-SniState, Get-SniInterface, Start-SniCapture,
    Stop-SniCapture, ConvertFrom-TsharkLine, Update-SniCache, Read-SniLines,
    Test-SniHealth, Resolve-SniAttribution
