# attribution-keys.tests.ps1 - attribution caches are keyed by the CANONICAL
# IP, like the raddr sampling.psm1 produces (review finding 2026-09-26: a
# source reporting '::ffff:a.b.c.d' or a differently-compressed IPv6 built
# keys no canonical raddr could ever hit). Platform-neutral: no ETW, tshark
# or DO cmdlets involved - every source is fed through its test seam.
. "$PSScriptRoot\_assert.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\dnsetw.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\snicapture.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\dolog.psm1" -Force

$now = [datetime]::UtcNow
function New-Conn([string]$Name, [string]$Ip, [int]$Port, [int]$ProcId = 4242) {
    @{ pid = $ProcId; name = $Name; raddr = $Ip; rport = $Port }
}

# --- ETW DNS: QueryResults parsing + dns_ip / dns_pidip ----------------------
$ips = @(ConvertFrom-DnsQueryResults -Text 'type:  5 cdn.example;::ffff:93.184.216.34;type:  28 2001:DB8:0:0::1;')
Assert-Equal '93.184.216.34' $ips[0] 'bare v4-mapped result canonicalized'
Assert-Equal '2001:db8::1'   $ips[1] 'AAAA result canonicalized (case/compression)'

$dns = New-DnsCaches
Update-DnsCaches -Caches $dns -NowUtc $now -Events @(
    @{ pid = 4242; domain = 'www.example.com'; ips = @('::ffff:93.184.216.34', '2001:DB8::0:1') })
$r = Resolve-DnsAttribution -Caches $dns -Conn (New-Conn 'proc' '93.184.216.34' 443)
Assert-Equal 'dns-pid' $r.source 'mapped ETW ip hits canonical raddr (pid key)'
Assert-Equal 'www.example.com' $r.domain 'dns-pid domain'
$r = Resolve-DnsAttribution -Caches $dns -Conn (New-Conn 'proc' '93.184.216.34' 443 -ProcId 1)
Assert-Equal 'dns-ip' $r.source 'mapped ETW ip hits canonical raddr (ambient key)'
$r = Resolve-DnsAttribution -Caches $dns -Conn (New-Conn 'proc' '2001:db8::1' 443 -ProcId 1)
Assert-Equal 'dns-ip' $r.source 'AAAA key canonical'
# lookup side canonicalizes too (defensive: raddr from another path)
$r = Resolve-DnsAttribution -Caches $dns -Conn (New-Conn 'proc' '::ffff:93.184.216.34' 443 -ProcId 1)
Assert-Equal 'dns-ip' $r.source 'non-canonical raddr still resolves'

# --- OS resolver cache ---------------------------------------------------------
$dns2 = New-DnsCaches
Update-DnsClientCache -Caches $dns2 -NowUtc $now -Entries @(
    @{ ip = '2001:0DB8:0000:0000:0000:0000:0000:0002'; domain = 'v6.example.'; ttl_sec = 300 }
    @{ ip = 'not-an-ip'; domain = 'junk.example'; ttl_sec = 300 })
$r = Resolve-DnsAttribution -Caches $dns2 -Conn (New-Conn 'proc' '2001:db8::2' 443 -ProcId 1)
Assert-Equal 'dns-cache' $r.source 'resolver-cache key canonical'
Assert-Equal 'v6.example' $r.domain 'resolver-cache domain'
Assert-Equal 1 $dns2.dns_cache.Count 'unparseable resolver entry skipped'

# --- SNI (tshark lines) --------------------------------------------------------
$sni = @{ sni = @{} }
$e = ConvertFrom-TsharkLine -Line "`t2001:DB8:0:0:0:0:0:3`t443`tapi.example.com"
Assert-Equal '2001:db8::3' $e.ip 'tshark v6 field canonicalized'
Update-SniCache -Caches $sni -Entry $e -NowUtc $now
$r = Resolve-SniAttribution -Caches $sni -Conn (New-Conn 'proc' '2001:db8::3' 443)
Assert-Equal 'sni' $r.source 'SNI entry hits canonical raddr'
Assert-Equal 'api.example.com' $r.domain 'SNI domain'
$e = ConvertFrom-TsharkLine -Line "93.184.216.35`t`t443`tv4.example.com"
Update-SniCache -Caches $sni -Entry $e -NowUtc $now
$r = Resolve-SniAttribution -Caches $sni -Conn (New-Conn 'proc' '::ffff:93.184.216.35' 443)
Assert-Equal 'sni' $r.source 'non-canonical raddr still resolves SNI'

# --- do-log (DO cache hosts) ---------------------------------------------------
Clear-DoLogCache
$prov = { @{ '::ffff:10.20.30.40' = 'dl.delivery.mp.microsoft.com' } }
$r = Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '10.20.30.40' 80) -Provider $prov
Assert-NotNull $r 'mapped DO cache host matches canonical raddr'
Assert-Equal 'dl.delivery.mp.microsoft.com' $r.domain 'do-log domain'
$r = Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '10.20.30.41' 80) -Provider $prov
Assert-Null $r 'different host does not match'

Complete-Tests
