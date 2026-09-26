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

function ConvertTo-CanonicalIp {
    # Canonical string form of an IP literal, $null when unparseable.
    # IPAddress.TryParse accepts many spellings of one address ('3405803786',
    # '10.1', '0x0a000001', '::ffff:10.0.0.1', '2001:db8::1%junk') - every
    # string comparison or URL built from the RAW input is bypassable. The
    # IPv6 scope id is dropped and IPv4-mapped IPv6 (dual-stack sockets
    # report these) collapses to plain IPv4.
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Ip)
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($addr.IsIPv4MappedToIPv6) { return $addr.MapToIPv4().ToString() }
        $addr.ScopeId = 0
    }
    return $addr.ToString()
}

function Get-EmbeddedIPv4 {
    # IPv4 address carried inside an IPv6 transition address, else $null:
    # NAT64 well-known prefix 64:ff9b::/96, deprecated IPv4-compatible ::/96,
    # 6to4 2002::/16 (bytes 2-5). Lookup guards must judge the embedded
    # address too - 64:ff9b::<own ip> would otherwise leak the own IP.
    param([Parameter(Mandatory)] [string]$Ip)
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }
    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
    $b = $addr.GetAddressBytes()
    $offset = -1
    if ((Test-IpInCidr -Ip $Ip -Cidr '64:ff9b::/96') -or (Test-IpInCidr -Ip $Ip -Cidr '::/96') -or
        (Test-IpInCidr -Ip $Ip -Cidr '::ffff:0:0:0/96')) { $offset = 12 }   # last: SIIT IPv4-translated (RFC 2765)
    elseif (Test-IpInCidr -Ip $Ip -Cidr '2002::/16') { $offset = 2 }
    if ($offset -lt 0) { return $null }
    return [System.Net.IPAddress]::new([byte[]]$b[$offset..($offset + 3)]).ToString()
}

function Test-NonRoutableIp {
    # Returns a reason string when $Ip must never be sent to external lookup
    # services, $null when it is a normal routable address.
    # Unparseable input returns 'invalid' (fail closed - never "routable").
    param([Parameter(Mandatory)] [string]$Ip)

    $canon = ConvertTo-CanonicalIp -Ip $Ip
    if (-not $canon) { return 'invalid' }
    $Ip = $canon
    $addr = [System.Net.IPAddress]::Parse($Ip)

    if ([System.Net.IPAddress]::IsLoopback($addr)) { return 'loopback' }

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($addr.IsIPv6LinkLocal)                  { return 'link-local' }
        if ($addr.IsIPv6Multicast)                  { return 'multicast' }
        if (Test-IpInCidr -Ip $Ip -Cidr 'fc00::/7') { return 'ula' }
        if ($Ip -eq '::')                           { return 'reserved' }
        # Teredo embeds the client's (obfuscated) public IPv4 - never send it
        if (Test-IpInCidr -Ip $Ip -Cidr '2001::/32') { return 'tunnel' }
        # RFC 8215 local-use NAT64: the IPv4's position depends on the
        # operator's prefix length (RFC 6052), so it cannot be extracted and
        # checked reliably - never looked up (fail closed)
        if (Test-IpInCidr -Ip $Ip -Cidr '64:ff9b:1::/48') { return 'tunnel' }
        # NB: the IPv4 embedded in NAT64/6to4 addresses is deliberately NOT
        # judged here - classify.psm1 maps 'loopback'/'link-local' to
        # local-noise, and 2002:7f00:1::1 is a real routable destination that
        # must stay visible. Embedded-IPv4 guarding belongs to the lookup
        # exclusion only (enrich.psm1 Test-ExcludedFromLookup).
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

Export-ModuleMember -Function Test-IpInCidr, Test-NonRoutableIp, ConvertTo-CymruName,
    ConvertTo-CanonicalIp, Get-EmbeddedIPv4
