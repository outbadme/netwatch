# dolog.psm1 - 'do-log' attribution source (docs/plans/DO-LOG-ATTRIBUTION-20260829.md).
#
# Attributes raw-IP connections from svchost/dosvc on port 80 via the
# machine's own Delivery Optimization records: when the connection's remote
# IP is recorded as a DO CacheHost, the IP is a Microsoft Connected Cache
# node (assigned dynamically by the DO GEO service - it ROTATES, which is
# why per-IP whitelisting cannot work). The attributed domain is the
# CONTENT origin (SourceURL host), not the endpoint.
#
# Consulted LAST in the attribution chain, only when every other source
# returned 'none'. All evidence-source failures fail OPEN to $null.

$script:DoLogCache   = $null
$script:DoLogCacheAt = [datetime]::MinValue
$script:DoLogWarned  = $false
$script:DoLogCacheSeconds = 600

function Clear-DoLogCache {
    # Test seam: reset the 10-minute evidence cache.
    $script:DoLogCache = $null
    $script:DoLogCacheAt = [datetime]::MinValue
    $script:DoLogWarned = $false
}

function Get-DoCacheHostMap {
    # @{ cacheHostIp -> sourceUrlHost }. -Provider replaces the evidence
    # source entirely (test seam; provider results are NOT cached).
    param([scriptblock]$Provider)
    if ($Provider) {
        try { return (& $Provider) } catch { return $null }   # fail OPEN
    }

    $now = [datetime]::UtcNow
    if ($null -ne $script:DoLogCache -and
        ($now - $script:DoLogCacheAt).TotalSeconds -lt $script:DoLogCacheSeconds) {
        return $script:DoLogCache
    }

    $map = @{}
    try {
        # Primary: structured status objects (unelevated OK).
        if (Get-Command Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue) {
            foreach ($e in @(Get-DeliveryOptimizationStatus -ErrorAction Stop)) {
                # Live-observed shapes (2026-08-29): CacheHost is a RELATIVE
                # System.Uri whose ToString() is the bare IP; SourceURL is an
                # absolute System.Uri - prefer its .Host over string parsing.
                $ch = if ($e.CacheHost) { [string]$e.CacheHost } else { $null }
                $srcHost = $null
                if ($e.SourceURL -is [uri] -and $e.SourceURL.IsAbsoluteUri) { $srcHost = $e.SourceURL.Host }
                elseif ($e.SourceURL -and "$($e.SourceURL)" -match '^https?://([^/]+)') { $srcHost = $Matches[1] }
                if ($ch -and $srcHost) { $map[$ch] = $srcHost }
            }
        }
        # Fallback: the full journal (admin-only; the production task runs
        # elevated). Conservative: only attribute when BOTH the cache host
        # and the content host are extractable from the same record.
        if ($map.Count -eq 0 -and (Get-Command Get-DeliveryOptimizationLog -ErrorAction SilentlyContinue)) {
            foreach ($e in @(Get-DeliveryOptimizationLog -ErrorAction Stop | Select-Object -First 500)) {
                $s = "$e"
                $host_ = $null; $src = $null
                if ($s -match 'cacheHost=([0-9A-Fa-f\.:]+)') { $host_ = $Matches[1] }
                if ($s -match 'SourceURL=https?://([^/\s"]+)') { $src = $Matches[1] }
                if ($host_ -and $src) { $map[$host_] = $src }
            }
        }
        $script:DoLogCache = $map
        $script:DoLogCacheAt = $now
    } catch {
        # fail OPEN: cache the (possibly partial) map anyway so a broken
        # source is retried only after the TTL, not on every connection.
        if (-not $script:DoLogWarned) {
            $script:DoLogWarned = $true
            Write-Warning "do-log attribution evidence unavailable: $($_.Exception.Message)"
        }
        $script:DoLogCache = $map
        $script:DoLogCacheAt = $now
    }
    return $script:DoLogCache
}

function Resolve-DoLogAttribution {
    # @{ source='do-log'; domain=<content host> } or $null.
    param(
        [Parameter(Mandatory)] $Conn,
        [scriptblock]$Provider
    )
    if ($Conn.name -notin @('svchost', 'dosvc')) { return $null }
    if ([int]$Conn.rport -ne 80) { return $null }
    $map = Get-DoCacheHostMap -Provider $Provider
    if (-not $map) { return $null }
    $ip = [string]$Conn.raddr
    if ($map.ContainsKey($ip)) {
        return @{ source = 'do-log'; domain = $map[$ip] }
    }
    return $null
}

Export-ModuleMember -Function Get-DoCacheHostMap, Resolve-DoLogAttribution, Clear-DoLogCache
