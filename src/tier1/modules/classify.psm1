# classify.psm1 - whitelist matching (D1 schema), browser policy, local-noise
# filter, residual queue with debounce (D2).
# Conn shape (normalized by sampling.psm1): hashtable with keys
#   pid name image_path image_exists command_line laddr lport raddr rport
#   state direction domain attribution_source

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'netutil.psm1') -Force

function Test-WhitelistMatch {
    # One whitelist entry vs one connection. Destination criteria (domains OR
    # domain_suffixes OR cidrs) are OR-ed; constraint criteria (processes,
    # ports, local_ports, direction) are AND-ed. Direction absent = outbound.
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] $Conn
    )
    $m = $Entry.match

    # direction constraint first (cheap): absent = outbound-only
    $wantDir = 'outbound'
    if ($m.PSObject.Properties['direction']) { $wantDir = $m.direction }
    if ($wantDir -ne 'any' -and $Conn.direction -ne $wantDir) { return $false }

    if ($m.PSObject.Properties['processes'] -and @($m.processes).Count -gt 0) {
        if ($Conn.name.ToLowerInvariant() -notin @($m.processes)) { return $false }
    }
    if ($m.PSObject.Properties['ports'] -and @($m.ports).Count -gt 0) {
        if ($Conn.rport -notin @($m.ports)) { return $false }
    }
    if ($m.PSObject.Properties['local_ports'] -and @($m.local_ports).Count -gt 0) {
        if ($Conn.lport -notin @($m.local_ports)) { return $false }
    }

    # destination criteria: any present criterion may match
    $domain = if ($Conn.domain) { $Conn.domain.ToLowerInvariant().TrimEnd('.') } else { $null }
    if ($domain -and $m.PSObject.Properties['domains']) {
        if ($domain -in @($m.domains)) { return $true }
    }
    if ($domain -and $m.PSObject.Properties['domain_suffixes']) {
        foreach ($suffix in @($m.domain_suffixes)) {
            $s = $suffix.ToLowerInvariant()
            if ($domain -eq $s -or $domain.EndsWith('.' + $s)) { return $true }
        }
    }
    if ($m.PSObject.Properties['cidrs']) {
        foreach ($cidr in @($m.cidrs)) {
            if (Test-IpInCidr -Ip $Conn.raddr -Cidr $cidr) { return $true }
        }
    }
    return $false
}

function Get-Classification {
    # 'whitelisted' | 'browser-attributed' | 'local-noise' | 'residual'
    # $HostAddresses: this host's own interface IPs - a remote end in that set
    # means the machine is talking to itself ("both ends local"). Other
    # private/tailnet peers are NOT noise and stay escalatable.
    param(
        [Parameter(Mandatory)] $Whitelist,
        [Parameter(Mandatory)] $Conn,
        [Parameter(Mandatory)] $Config,
        $HostAddresses
    )
    # own-machine noise: loopback / link-local / both ends this host
    $reason = Test-NonRoutableIp -Ip $Conn.raddr
    if ($reason -in 'loopback', 'link-local') { return 'local-noise' }
    if ($HostAddresses -and $HostAddresses.Contains($Conn.raddr)) { return 'local-noise' }

    foreach ($entry in $Whitelist.entries) {
        if (Test-WhitelistMatch -Entry $entry -Conn $Conn) { return 'whitelisted' }
    }

    # browser policy: attributed browser traffic = clean-logged; raw-IP browser
    # traffic stays escalatable (GOAL: DoH churn is unwhitelistable but SNI/DNS
    # attribution must exist)
    if ($Conn.name.ToLowerInvariant() -in @($Config.classify.browser_attributed_ok)) {
        if ($Conn.attribution_source -ne 'none' -and $Conn.domain) { return 'browser-attributed' }
    }
    return 'residual'
}

function Get-ResidualKey {
    param([Parameter(Mandatory)] $Conn)
    $mid = if ($Conn.domain) { $Conn.domain.ToLowerInvariant().TrimEnd('.') } else { $Conn.raddr }
    return '{0}|{1}|{2}' -f $Conn.name.ToLowerInvariant(), $mid, $Conn.rport
}

function Update-ResidualQueue {
    # Registers/updates a residual connection. Returns the key. A later
    # attribution changes the key (ip -> domain): both keys coexist briefly;
    # the ip-keyed entry ages out unclaimed (accepted, keeps logic simple).
    param(
        [Parameter(Mandatory)] [hashtable]$Queue,
        [Parameter(Mandatory)] $Conn,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    $key = Get-ResidualKey -Conn $Conn
    if (-not $Queue.ContainsKey($key)) {
        $Queue[$key] = @{
            first_seen    = $NowUtc
            last_seen     = $NowUtc
            samples       = 1
            snapshot      = $Conn
            state_history = @($Conn.state)
            pending       = $false
            immediate     = $false   # sticky F14/F15 flag; set by the main loop
            enriched      = $null
        }
    }
    else {
        $q = $Queue[$key]
        # D2: samples counts SAMPLING ROUNDS, not connection instances -
        # parallel conns to the same endpoint within one tick share $NowUtc
        # and must count once (live smoke run escalated on tick 1 otherwise)
        if ($q.last_seen -ne $NowUtc) { $q.samples++ }
        $q.last_seen = $NowUtc
        $q.snapshot = $Conn
        if ($q.state_history[-1] -ne $Conn.state) { $q.state_history += $Conn.state }
    }
    return $key
}

function Remove-ReclassifiedQueueKeys {
    # Whitelist hot-reload aftermath: re-classify every queued snapshot against
    # the NEW whitelist and evict entries that are no longer 'residual'.
    # Without this a key the operator just whitelisted keeps escalating on its
    # stale queue entry (live 2026-08-27: node|api.deepseek.com|443 whitelisted
    # 18:36Z, still shipped in packet 20260827-192012-394 at 19:20Z). Pending
    # (alarm-suspended) entries are evicted too - whitelisting IS the operator
    # resolution. Returns the evicted keys.
    param(
        [Parameter(Mandatory)] [hashtable]$Queue,
        [Parameter(Mandatory)] $Whitelist,
        [Parameter(Mandatory)] $Config,
        $HostAddresses
    )
    $removed = foreach ($k in @($Queue.Keys)) {
        $class = Get-Classification -Whitelist $Whitelist -Conn $Queue[$k].snapshot `
            -Config $Config -HostAddresses $HostAddresses
        if ($class -ne 'residual') {
            $Queue.Remove($k)
            $k
        }
    }
    return @($removed)
}

function Get-EscalatableKeys {
    # D2 debounce: seen in >= min_samples samples OR first-seen age >=
    # min_age_sec. Skips suppressed (prior CLEAN) and pending (already sent /
    # alarm-suspended) keys. $IsSuppressed: scriptblock key -> bool, so this
    # module stays storage-agnostic.
    param(
        [Parameter(Mandatory)] [hashtable]$Queue,
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [datetime]$NowUtc,
        [Parameter(Mandatory)] [scriptblock]$IsSuppressed
    )
    $minSamples = $Config.debounce.min_samples
    $minAge     = $Config.debounce.min_age_sec
    $result = foreach ($key in $Queue.Keys) {
        $q = $Queue[$key]
        if ($q.pending) { continue }
        $age = ($NowUtc - $q.first_seen).TotalSeconds
        if ($q.samples -ge $minSamples -or $age -ge $minAge) {
            if (-not (& $IsSuppressed $key)) { $key }
        }
    }
    return @($result)
}

Export-ModuleMember -Function Test-WhitelistMatch, Get-Classification,
    Get-ResidualKey, Update-ResidualQueue, Get-EscalatableKeys,
    Remove-ReclassifiedQueueKeys
