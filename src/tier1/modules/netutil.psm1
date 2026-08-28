# netutil.psm1 - shared IP/CIDR math for netwatch Tier 1 (pure functions).
# Used by classify.psm1 (whitelist CIDR entries) and enrich.psm1 (lookup
# exclusions). The Tier-2 check-reputation.ps1 tool deliberately duplicates a
# minimal copy of these checks (defense in depth, no shared import).

Set-StrictMode -Version Latest

function Test-IpInCidr {
    # True when $Ip falls inside $Cidr (IPv4 or IPv6, prefix-bit compare).
    # Malformed input => $false (callers treat unparseable as "no match"),
    # never an exception.
    param(
        [Parameter(Mandatory)] [string]$Ip,
        [Parameter(Mandatory)] [string]$Cidr
    )
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $false }

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $base = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$base)) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }

    if ($addr.AddressFamily -ne $base.AddressFamily) { return $false }
    $addrBytes = $addr.GetAddressBytes()
    $baseBytes = $base.GetAddressBytes()
    if ($prefix -lt 0 -or $prefix -gt (8 * $addrBytes.Length)) { return $false }

    $fullBytes = [math]::Floor($prefix / 8)
    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($addrBytes[$i] -ne $baseBytes[$i]) { return $false }
    }
    $remBits = $prefix % 8
    if ($remBits -gt 0) {
        $mask = (0xFF -shl (8 - $remBits)) -band 0xFF
        if (($addrBytes[$fullBytes] -band $mask) -ne ($baseBytes[$fullBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Test-NonRoutableIp {
    # Returns a reason string when $Ip must never be sent to external lookup
    # services, $null when it is a normal routable address.
    # Unparseable input returns 'invalid' (fail closed - never "routable").
    param([Parameter(Mandatory)] [string]$Ip)

    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return 'invalid' }

    if ([System.Net.IPAddress]::IsLoopback($addr)) { return 'loopback' }

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($addr.IsIPv6LinkLocal)                  { return 'link-local' }
        if ($addr.IsIPv6Multicast)                  { return 'multicast' }
        if (Test-IpInCidr -Ip $Ip -Cidr 'fc00::/7') { return 'ula' }
        return $null
    }

    if (Test-IpInCidr -Ip $Ip -Cidr '169.254.0.0/16') { return 'link-local' }
    foreach ($c in '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') {
        if (Test-IpInCidr -Ip $Ip -Cidr $c) { return 'rfc1918' }
    }
    if (Test-IpInCidr -Ip $Ip -Cidr '100.64.0.0/10') { return 'cgnat' }
    if (Test-IpInCidr -Ip $Ip -Cidr '224.0.0.0/4')   { return 'multicast' }
    foreach ($c in '0.0.0.0/8', '240.0.0.0/4') {
        if (Test-IpInCidr -Ip $Ip -Cidr $c) { return 'reserved' }
    }
    return $null
}

function ConvertTo-CymruName {
    # Team Cymru origin-ASN DNS TXT query name for an IP; $null on bad input.
    # v4: reversed octets + .origin.asn.cymru.com
    # v6: reversed nibbles of the full 32-hex-digit form + .origin6.asn.cymru.com
    param([Parameter(Mandatory)] [string]$Ip)

    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }

    $bytes = $addr.GetAddressBytes()
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        [array]::Reverse($bytes)
        return (($bytes | ForEach-Object { $_.ToString() }) -join '.') + '.origin.asn.cymru.com'
    }
    $nibbles = foreach ($b in $bytes) { '{0:x}' -f (($b -shr 4) -band 0xF); '{0:x}' -f ($b -band 0xF) }
    [array]::Reverse($nibbles)
    return ($nibbles -join '.') + '.origin6.asn.cymru.com'
}

Export-ModuleMember -Function Test-IpInCidr, Test-NonRoutableIp, ConvertTo-CymruName
