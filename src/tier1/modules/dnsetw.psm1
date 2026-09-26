# dnsetw.psm1 - bookmarked reader for Microsoft-Windows-DNS-Client/Operational
# events 3006/3008 (domain + PID + resolved IPs). Bookmark = last EventRecordID
# persisted in state\etw-bookmark.xml (EventBookmark has no public
# serialization; an EventRecordID XPath filter is the documented equivalent).
# Channel disabled/no access => health 'unavailable' (F5), never fatal.

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'state.psm1')
Import-Module (Join-Path $PSScriptRoot 'netutil.psm1')

$script:ChannelName = 'Microsoft-Windows-DNS-Client/Operational'
$script:CacheTtlHours = 2

function Test-DnsEtwAvailable {
    # 'ok' when the channel exists AND is enabled; 'unavailable' otherwise.
    # An empty-but-enabled channel is ok; disabled (this machine today, per
    # operator probe 2026-08-27) is unavailable until install/enable-etw.ps1.
    try {
        $cfg = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new($script:ChannelName)
        if ($cfg.IsEnabled) { return 'ok' }
        return 'unavailable'
    }
    catch {
        return 'unavailable'
    }
}

function ConvertFrom-DnsQueryResults {
    # 3008 QueryResults string -> resolved IP literals.
    # Format: "type:  5 cname;type:  1 1.2.3.4;" (5=CNAME skipped, 1=A,
    # 28=AAAA); some events carry bare "ip;" entries. IPs are returned in
    # canonical form (ConvertTo-CanonicalIp): sampling canonicalizes raddr, so
    # a '::ffff:a.b.c.d' key here would never match a connection.
    param([AllowEmptyString()] [string]$Text)
    $ips = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($chunk in $Text.Split(';')) {
        $c = $chunk.Trim()
        if (-not $c) { continue }
        $m = [regex]::Match($c, '^type:\s*(\d+)\s+(.+)$')
        if ($m.Success) {
            if ($m.Groups[1].Value -in '1', '28') {
                $val = $m.Groups[2].Value.Trim()
                $addr = $null
                if ([System.Net.IPAddress]::TryParse($val, [ref]$addr)) { $ips.Add((ConvertTo-CanonicalIp -Ip $val)) }
            }
            continue
        }
        $addr = $null
        if ([System.Net.IPAddress]::TryParse($c, [ref]$addr)) { $ips.Add((ConvertTo-CanonicalIp -Ip $c)) }
    }
    return @($ips)
}

function ConvertFrom-DnsEventXml {
    # One event's XML -> @{ record_id; pid; domain; ips[] }.
    param([Parameter(Mandatory)] [string]$Xml)
    $doc = [xml]$Xml
    $sys = $doc.Event.System
    $data = @{}
    $eventData = $doc.Event.PSObject.Properties['EventData']?.Value
    if ($eventData -and $eventData.PSObject.Properties['Data']) {
        foreach ($d in @($eventData.Data)) {
            $name = $d.PSObject.Properties['Name']?.Value
            $text = $d.PSObject.Properties['#text']?.Value
            if ($name) { $data[$name] = [string]$text }
        }
    }
    $results = if ($data.ContainsKey('QueryResults')) { $data['QueryResults'] } else { '' }
    return @{
        record_id = [long]$sys.EventRecordID
        pid       = [int]$sys.Execution.ProcessID
        domain    = if ($data.ContainsKey('QueryName')) { ([string]$data['QueryName']).ToLowerInvariant().TrimEnd('.') } else { $null }
        ips       = @(ConvertFrom-DnsQueryResults -Text $results)
    }
}

function Get-DnsBookmark {
    param([Parameter(Mandatory)] $Config)
    $file = Join-Path $Config.paths.state_root 'state\etw-bookmark.xml'
    if (-not (Test-Path -LiteralPath $file)) { return [long]0 }
    try {
        $doc = [xml](Get-Content -LiteralPath $file -Raw)
        return [long]$doc.bookmark.record
    }
    catch {
        Write-OpLog -Config $Config -Level WARN -Message 'etw bookmark corrupt, resetting to 0'
        return [long]0
    }
}

function Set-DnsBookmark {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [long]$RecordId
    )
    $file = Join-Path $Config.paths.state_root 'state\etw-bookmark.xml'
    "<bookmark record=""$RecordId"" />" | Set-Content -LiteralPath $file -Encoding utf8
}

function Read-DnsEvents {
    # Drains events 3006/3008 newer than the bookmark; advances the bookmark.
    # Any reader failure returns @() (health handled separately via
    # Test-DnsEtwAvailable) - attribution loss is degraded mode, not a crash.
    param([Parameter(Mandatory)] $Config)
    $events = [System.Collections.Generic.List[object]]::new()
    try {
        $last = Get-DnsBookmark -Config $Config
        $xpath = "*[System[(EventID=3006 or EventID=3008) and EventRecordID > $last]]"
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $script:ChannelName,
            [System.Diagnostics.Eventing.Reader.PathType]::LogName,
            $xpath)
        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        try {
            $maxId = $last
            while ($true) {
                $ev = $reader.ReadEvent()
                if ($null -eq $ev) { break }
                try {
                    $rec = ConvertFrom-DnsEventXml -Xml $ev.ToXml()
                    if ($rec.record_id -gt $maxId) { $maxId = $rec.record_id }
                    if ($rec.domain) { $events.Add($rec) }
                }
                finally { $ev.Dispose() }
            }
            if ($maxId -gt $last) { Set-DnsBookmark -Config $Config -RecordId $maxId }
        }
        finally { $reader.Dispose() }
    }
    catch {
        Write-OpLog -Config $Config -Level TRACE -Message "dns etw read failed: $($_.Exception.Message)"
    }
    return @($events)
}

function New-DnsCaches {
    return @{
        dns_ip    = @{}   # ip -> @{ domains = [list]; expires }       (ETW, ambient)
        dns_pidip = @{}   # "pid|ip" -> @{ domain; expires }           (ETW, per-process)
        dns_cache = @{}   # ip -> @{ domain; expires }                 (OS resolver cache)
    }
}

function Update-DnsClientCache {
    # OS resolver cache as an ambient attribution source (repair 2026-08-27):
    # SNI is best-effort behind the VPN's kernel data-channel offload and ETW
    # only sees lookups made while netwatch runs; Get-DnsClientCache knows
    # ip -> queried-name regardless of both. Entry lifetime = the record's own
    # remaining TTL, capped at the module cache TTL. $Entries is the test
    # seam (@(@{ip;domain;ttl_sec})); omitted = live read, failures tolerated.
    param(
        [Parameter(Mandatory)] [hashtable]$Caches,
        [Parameter(Mandatory)] [datetime]$NowUtc,
        [array]$Entries = $null
    )
    if ($null -eq $Entries) {
        $Entries = @()
        try {
            foreach ($r in @(Get-DnsClientCache -Status Success -Type A, AAAA -ErrorAction Stop)) {
                if ($r.Data -and $r.Entry) {
                    $Entries += @{ ip = [string]$r.Data; domain = [string]$r.Entry; ttl_sec = [int]$r.TimeToLive }
                }
            }
        }
        catch { $Entries = @() }   # cmdlet/service unavailable: keep what we have
    }
    $capSec = 3600 * $script:CacheTtlHours
    foreach ($e in $Entries) {
        $ttl = [math]::Min([math]::Max([int]$e.ttl_sec, 0), $capSec)
        if ($ttl -le 0) { continue }
        $ipKey = ConvertTo-CanonicalIp -Ip ([string]$e.ip)
        if (-not $ipKey) { continue }
        $Caches.dns_cache[$ipKey] = @{
            domain  = ([string]$e.domain).ToLowerInvariant().TrimEnd('.')
            expires = $NowUtc.AddSeconds($ttl)
        }
    }
    foreach ($k in @($Caches.dns_cache.Keys)) {
        if ($Caches.dns_cache[$k].expires -le $NowUtc) { $Caches.dns_cache.Remove($k) }
    }
}

function Update-DnsCaches {
    param(
        [Parameter(Mandatory)] [hashtable]$Caches,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Events,
        [Parameter(Mandatory)] [datetime]$NowUtc
    )
    $expires = $NowUtc.AddHours($script:CacheTtlHours)
    foreach ($e in $Events) {
        foreach ($rawIp in $e.ips) {
            $ip = ConvertTo-CanonicalIp -Ip ([string]$rawIp)
            if (-not $ip) { continue }
            if (-not $Caches.dns_ip.ContainsKey($ip)) {
                $Caches.dns_ip[$ip] = @{ domains = [System.Collections.Generic.List[string]]::new(); expires = $expires }
            }
            $entry = $Caches.dns_ip[$ip]
            $entry.expires = $expires
            if ($e.domain -notin $entry.domains) { $entry.domains.Add($e.domain) }
            $Caches.dns_pidip["$($e.pid)|$ip"] = @{ domain = $e.domain; expires = $expires }
        }
    }
    # prune expired
    foreach ($k in @($Caches.dns_ip.Keys)) {
        if ($Caches.dns_ip[$k].expires -le $NowUtc) { $Caches.dns_ip.Remove($k) }
    }
    foreach ($k in @($Caches.dns_pidip.Keys)) {
        if ($Caches.dns_pidip[$k].expires -le $NowUtc) { $Caches.dns_pidip.Remove($k) }
    }
}

function Resolve-DnsAttribution {
    # dns-pid (precise) > dns-ip (ETW ambient) > dns-cache (OS resolver
    # cache, no pid knowledge); 'none' otherwise.
    param(
        [Parameter(Mandatory)] [hashtable]$Caches,
        [Parameter(Mandatory)] $Conn
    )
    # keys are canonical (see ConvertFrom-DnsQueryResults); so is the lookup
    $ip = ConvertTo-CanonicalIp -Ip ([string]$Conn.raddr)
    if (-not $ip) { $ip = [string]$Conn.raddr }
    $pidKey = "$($Conn.pid)|$ip"
    if ($Caches.dns_pidip.ContainsKey($pidKey)) {
        return @{ source = 'dns-pid'; domain = $Caches.dns_pidip[$pidKey].domain }
    }
    if ($Caches.dns_ip.ContainsKey($ip)) {
        $domains = $Caches.dns_ip[$ip].domains
        if ($domains.Count -gt 0) {
            return @{ source = 'dns-ip'; domain = $domains[$domains.Count - 1] }   # most recent
        }
    }
    if ($Caches.ContainsKey('dns_cache') -and $Caches.dns_cache.ContainsKey($ip)) {
        return @{ source = 'dns-cache'; domain = $Caches.dns_cache[$ip].domain }
    }
    return @{ source = 'none'; domain = $null }
}

Export-ModuleMember -Function Test-DnsEtwAvailable, ConvertFrom-DnsQueryResults,
    ConvertFrom-DnsEventXml, Get-DnsBookmark, Set-DnsBookmark, Read-DnsEvents,
    New-DnsCaches, Update-DnsCaches, Update-DnsClientCache, Resolve-DnsAttribution
