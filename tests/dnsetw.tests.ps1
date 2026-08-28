# dnsetw.tests.ps1 - DNS-Client ETW parsing, caches, bookmark, availability.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\dnsetw.psm1" -Force

# --- QueryResults parser -----------------------------------------------------
$ips = @(ConvertFrom-DnsQueryResults -Text 'type:  5 some-cname.example.net;type:  1 93.184.216.34;')
Assert-Equal 1 $ips.Count 'one A record extracted, cname skipped'
Assert-Equal '93.184.216.34' $ips[0] 'A value parsed'

$ips = @(ConvertFrom-DnsQueryResults -Text 'type:  28 2606:2800:220:1:248:1893:25c8:1946;type:  1 93.184.216.34;')
Assert-Equal 2 $ips.Count 'AAAA + A both extracted'
Assert-True ('2606:2800:220:1:248:1893:25c8:1946' -in $ips) 'AAAA parsed'

$ips = @(ConvertFrom-DnsQueryResults -Text '')
Assert-Equal 0 $ips.Count 'empty results tolerated'

# bare-ip form (some 3008 events carry the ip without type prefix)
$ips = @(ConvertFrom-DnsQueryResults -Text '93.184.216.34;')
Assert-Equal '93.184.216.34' $ips[0] 'bare ip form parsed'

# --- event XML parser --------------------------------------------------------
$xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>3008</EventID>
    <EventRecordID>4242</EventRecordID>
    <Execution ProcessID="7777" ThreadID="1" />
  </System>
  <EventData>
    <Data Name="QueryName">api.example.com</Data>
    <Data Name="QueryType">1</Data>
    <Data Name="QueryResults">type:  5 edge.example.net;type:  1 203.0.113.10;</Data>
  </EventData>
</Event>
'@
$rec = ConvertFrom-DnsEventXml -Xml $xml
Assert-Equal 7777 $rec.pid 'pid from Execution'
Assert-Equal 'api.example.com' $rec.domain 'domain from QueryName'
Assert-Equal 4242 $rec.record_id 'record id extracted'
Assert-True ('203.0.113.10' -in $rec.ips) 'resolved ip extracted'

# --- caches + attribution ----------------------------------------------------
$caches = New-DnsCaches
$now = [datetime]::UtcNow
Update-DnsCaches -Caches $caches -Events @($rec) -NowUtc $now
$conn = @{ pid = 7777; raddr = '203.0.113.10' }
$att = Resolve-DnsAttribution -Caches $caches -Conn $conn
Assert-Equal 'dns-pid' $att.source 'pid+ip preferred'
Assert-Equal 'api.example.com' $att.domain 'domain attributed'

$connOtherPid = @{ pid = 1; raddr = '203.0.113.10' }
$att = Resolve-DnsAttribution -Caches $caches -Conn $connOtherPid
Assert-Equal 'dns-ip' $att.source 'ip-only fallback'
Assert-Equal 'api.example.com' $att.domain 'domain attributed via ip'

$connMiss = @{ pid = 1; raddr = '198.51.100.99' }
$att = Resolve-DnsAttribution -Caches $caches -Conn $connMiss
Assert-Equal 'none' $att.source 'no attribution'

# TTL expiry: entry inserted 3 h ago is pruned by the next tick's update call
$caches2 = New-DnsCaches
Update-DnsCaches -Caches $caches2 -Events @($rec) -NowUtc $now.AddHours(-3)
Update-DnsCaches -Caches $caches2 -Events @() -NowUtc $now
$att = Resolve-DnsAttribution -Caches $caches2 -Conn $conn
Assert-Equal 'none' $att.source 'expired entries pruned (2h TTL)'

# --- OS DNS client cache as attribution source (2026-08-27 repair item 2) ----
# SNI is best-effort on this box (VPN data-channel offload hides inner TLS)
# and ETW misses lookups done before netwatch started. The OS resolver cache
# knows raddr->domain regardless of either. Lower precedence than both ETW
# forms; pruned by the record's own TTL.
$caches3 = New-DnsCaches
Update-DnsClientCache -Caches $caches3 -NowUtc $now -Entries @(
    @{ ip = '203.0.113.44'; domain = 'cdn.example.org'; ttl_sec = 300 }
    @{ ip = '203.0.113.10'; domain = 'stale.example.org'; ttl_sec = 300 }
)
$att = Resolve-DnsAttribution -Caches $caches3 -Conn @{ pid = 1; raddr = '203.0.113.44' }
Assert-Equal 'dns-cache' $att.source 'os cache attributes unseen ip'
Assert-Equal 'cdn.example.org' $att.domain 'os cache domain'

# precedence: ETW pid/ip answers win over the ambient os cache
Update-DnsCaches -Caches $caches3 -Events @($rec) -NowUtc $now
$att = Resolve-DnsAttribution -Caches $caches3 -Conn $conn
Assert-Equal 'dns-pid' $att.source 'etw pid entry outranks os cache'
$att = Resolve-DnsAttribution -Caches $caches3 -Conn $connOtherPid
Assert-Equal 'dns-ip' $att.source 'etw ip entry outranks os cache'

# record TTL respected: expired entry pruned by the next update
$caches4 = New-DnsCaches
Update-DnsClientCache -Caches $caches4 -NowUtc $now.AddSeconds(-600) -Entries @(
    @{ ip = '203.0.113.44'; domain = 'cdn.example.org'; ttl_sec = 300 }
)
Update-DnsClientCache -Caches $caches4 -NowUtc $now -Entries @()
$att = Resolve-DnsAttribution -Caches $caches4 -Conn @{ pid = 1; raddr = '203.0.113.44' }
Assert-Equal 'none' $att.source 'os cache entry expired with its TTL'

# live read path never throws (entries omitted = real Get-DnsClientCache)
$cachesLive = New-DnsCaches
Update-DnsClientCache -Caches $cachesLive -NowUtc $now
Assert-True ($cachesLive.dns_cache.Count -ge 0) 'live os-cache read tolerated'
Write-Host "live os dns cache entries mapped: $($cachesLive.dns_cache.Count)"

# --- bookmark round-trip -----------------------------------------------------
$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg
    Assert-Equal 0 (Get-DnsBookmark -Config $cfg) 'fresh bookmark is 0'
    Set-DnsBookmark -Config $cfg -RecordId 41
    Assert-Equal 41 (Get-DnsBookmark -Config $cfg) 'bookmark round-trip'
    # corrupt bookmark resets to 0, not crash
    Set-Content (Join-Path $root 'state\etw-bookmark.xml') 'garbage <<'
    Assert-Equal 0 (Get-DnsBookmark -Config $cfg) 'corrupt bookmark resets to 0'

    # --- live availability probe (no admin, channel currently disabled) ------
    $avail = Test-DnsEtwAvailable
    Assert-True ($avail -in 'ok', 'unavailable') "probe returns a health value (got: $avail)"
    Write-Host "live dns-etw availability on this machine: $avail (operator report says channel disabled -> expect unavailable until enable-etw.ps1 is run)"

    # Read-DnsEvents must not throw even when unavailable
    $events = @(Read-DnsEvents -Config $cfg)
    Assert-True ($events.Count -ge 0) 'read returns array, never throws'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
