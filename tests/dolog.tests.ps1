# dolog.tests.ps1 - 'do-log' attribution source (DO-LOG-ATTRIBUTION-20260829).
. "$PSScriptRoot\_assert.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\dolog.psm1" -Force

function New-Conn([string]$name, [string]$ip, [int]$port) {
    return @{ pid = 1; name = $name; raddr = $ip; rport = $port; state = 'Established'; direction = 'outbound' }
}
$host1 = '1d.tlu.dl.delivery.mp.microsoft.com'
$map = @{ '193.57.46.213' = $host1; '193.57.46.231' = $host1 }

# --- 1. hit: svchost:80 to a CacheHost IP -> do-log + content host ---------
$a = Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.231' 80) -Provider { $map }
Assert-Equal 'do-log' $a.source 'hit: source is do-log'
Assert-Equal $host1 $a.domain 'hit: domain is the SourceURL content host'

# --- 2. miss: unknown IP -> $null ------------------------------------------
Assert-Null (Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '203.0.113.9' 80) -Provider { $map }) 'miss: unknown IP stays none'

# --- 3. wrong process -> $null even for a known CacheHost IP ---------------
Assert-Null (Resolve-DoLogAttribution -Conn (New-Conn 'chrome' '193.57.46.213' 80) -Provider { $map }) 'gate: only svchost/dosvc'

# --- 4. wrong port -> $null (7680 peers are a separate whitelist class) ----
Assert-Null (Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.213' 7680) -Provider { $map }) 'gate: only port 80'

# --- 5. dosvc process name also matches ------------------------------------
$a5 = Resolve-DoLogAttribution -Conn (New-Conn 'dosvc' '193.57.46.213' 80) -Provider { $map }
Assert-Equal 'do-log' $a5.source 'dosvc process matches too'

# --- 6. provider failure / absence -> $null, never throws ------------------
Assert-Null (Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.213' 80) -Provider { return $null }) 'provider null -> none'
Assert-Null (Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.213' 80) -Provider { throw 'admin required' }) 'provider throw propagates? NO - must be contained'

# --- 7. map building from real-shaped status objects + cache TTL ----------
# Shadow the cmdlets with global fakes inside THIS test process only.
$script:fakeCalls = 0
function global:Get-DeliveryOptimizationStatus {
    $script:fakeCalls++
    @(
        [pscustomobject]@{ CacheHost = '193.57.46.213'; SourceURL = 'http://1d.tlu.dl.delivery.mp.microsoft.com/files/abc?P1=1' },
        [pscustomobject]@{ CacheHost = '';                SourceURL = 'http://f.c2r.ts.cdn.office.net/pr/x' },
        [pscustomobject]@{ CacheHost = '193.57.46.231';   SourceURL = $null }
    )
}
function global:Get-DeliveryOptimizationLog { throw 'admin required' }
try {
    Clear-DoLogCache
    $m1 = Get-DoCacheHostMap
    Assert-Equal 1 $script:fakeCalls 'status cmdlet called once'
    Assert-Equal 1 $m1.Count 'only entries with BOTH CacheHost and SourceURL host count'
    Assert-Equal '1d.tlu.dl.delivery.mp.microsoft.com' $m1['193.57.46.213'] 'content host extracted from SourceURL'
    Assert-False ($m1.ContainsKey('193.57.46.231')) 'entry without SourceURL not attributed (never invent a domain)'

    $m2 = Get-DoCacheHostMap
    Assert-Equal 1 $script:fakeCalls 'cache TTL: no second query within the window'
    Assert-True ($m2 -eq $m1) 'cache returns the same map object'

    $a7 = Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.213' 80)
    Assert-Equal 'do-log' $a7.source 'end-to-end via the real (shadowed) evidence source'

    Clear-DoLogCache
    $null = Get-DoCacheHostMap
    Assert-Equal 2 $script:fakeCalls 'Clear-DoLogCache forces a re-query'

    # reality-pinned shapes (live 2026-08-29): CacheHost = RELATIVE System.Uri
    # (ToString = bare IP), SourceURL = ABSOLUTE System.Uri
    function global:Get-DeliveryOptimizationStatus {
        $script:fakeCalls++
        @( [pscustomobject]@{ CacheHost = [uri]'193.57.46.231'; SourceURL = [uri]'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/xyz?P1=1' } )
    }
    Clear-DoLogCache
    $mReal = Get-DoCacheHostMap
    Assert-True ($mReal.ContainsKey('193.57.46.231')) 'real shape: relative-Uri CacheHost normalizes to bare IP key'
    Assert-Equal 'msedge.b.tlu.dl.delivery.mp.microsoft.com' $mReal['193.57.46.231'] 'real shape: content host from absolute-Uri SourceURL'
    $aReal = Resolve-DoLogAttribution -Conn (New-Conn 'svchost' '193.57.46.231' 80)
    Assert-Equal 'do-log' $aReal.source 'real shape: end-to-end attribution works'
} finally {
    Remove-Item Function:\Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-DeliveryOptimizationLog -ErrorAction SilentlyContinue
}

Complete-Tests
