# enrich.psm1 - own-IP detection/exclusion (fail-closed, F7/F8) and Team Cymru
# ASN enrichment for escalatable residuals. Own/private/CGNAT IPs never go to
# ANY external lookup; the same guard is duplicated inside the Tier-2
# check-reputation tool (defense in depth).

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'netutil.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'state.psm1')

$script:OwnIpGraceDays = 7

function Get-OwnIpFile {
    param([Parameter(Mandatory)] $Config)
    return Join-Path $Config.paths.state_root 'state\ownip.json'
}

function Update-OwnIp {
    # Detects the current public IP (default: OpenDNS myip trick, A + AAAA) and
    # maintains state\ownip.json. On failure keeps last-known + static and only
    # logs (F7 fail-closed). $ResolveFn override for tests.
    param(
        [Parameter(Mandatory)] $Config,
        [scriptblock]$ResolveFn
    )
    if (-not $ResolveFn) {
        $ResolveFn = {
            $ips = @()
            foreach ($type in 'A', 'AAAA') {
                try {
                    $r = Resolve-DnsName -Name 'myip.opendns.com' -Server 'resolver1.opendns.com' `
                        -Type $type -QuickTimeout -ErrorAction Stop
                    $ips += @($r | Where-Object IPAddress | ForEach-Object IPAddress)
                }
                catch {}
            }
            if (-not $ips) { throw 'own-ip detection failed (both A and AAAA)' }
            return $ips
        }
    }

    $file = Get-OwnIpFile -Config $Config
    $now = [datetime]::UtcNow
    $state = $null
    if (Test-Path -LiteralPath $file) {
        try { $state = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json }
        catch {
            Write-OpLog -Config $Config -Level WARN -Message "ownip.json unreadable, rebuilding: $($_.Exception.Message)"
        }
    }
    if ($null -eq $state) {
        $state = [pscustomobject]@{
            detected = @(); last_known = @(); recorded_static = @()
            previous = @(); detected_at = $null
        }
    }
    # old-format/foreign files: every field must exist under StrictMode or the
    # monitor dies AT STARTUP (reviewer 2026-08-28) - carry over what is
    # present, default the rest
    foreach ($f in 'detected', 'last_known', 'recorded_static', 'previous') {
        if (-not $state.PSObject.Properties[$f]) { $state | Add-Member -NotePropertyName $f -NotePropertyValue @() }
    }
    if (-not $state.PSObject.Properties['detected_at']) {
        $state | Add-Member -NotePropertyName detected_at -NotePropertyValue $null
    }
    $state.recorded_static = @($Config.own_ip.recorded_static)

    try {
        $ips = @(& $ResolveFn)
        if (-not $ips) { throw 'resolver returned nothing' }
        # retire previously-detected IPs that vanished (7-day grace vs flapping)
        $retired = @($state.previous)
        foreach ($old in @($state.detected)) {
            if ($old -notin $ips -and $old -notin @($retired | ForEach-Object ip)) {
                $retired += [pscustomobject]@{ ip = $old; retired_at = $now.ToString('o') }
            }
        }
        $state.previous    = $retired
        $state.last_known  = $ips      # last successful detection; retired IPs live in previous (7-day grace)
        $state.detected    = $ips
        $state.detected_at = $now.ToString('o')
    }
    catch {
        Write-OpLog -Config $Config -Level WARN -Message "own-ip detection failed, keeping last-known set (fail closed): $($_.Exception.Message)"
    }
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding utf8
}

function Get-OwnIpExclusions {
    # Exclusion set = detected + last-known + recorded static + unexpired
    # retired (grace). NEVER empty: static values come from config even when
    # the state file is missing.
    param([Parameter(Mandatory)] $Config)
    $set = @($Config.own_ip.recorded_static)
    $file = Get-OwnIpFile -Config $Config
    if (Test-Path -LiteralPath $file) {
        try {
            $state = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            $set += @($state.detected) + @($state.last_known) + @($state.recorded_static)
            $cutoff = [datetime]::UtcNow.AddDays(-$script:OwnIpGraceDays)
            foreach ($p in @($state.previous)) {
                if ([datetime]::Parse($p.retired_at).ToUniversalTime() -gt $cutoff) { $set += $p.ip }
            }
        }
        catch {
            Write-OpLog -Config $Config -Level ERROR -Message "ownip.json unreadable, using static-only exclusions: $($_.Exception.Message)"
        }
    }
    return @($set | Where-Object { $_ } | Select-Object -Unique)
}

function Test-ExcludedFromLookup {
    # Reason string when this IP must not be sent to Cymru/AbuseIPDB/VT,
    # else $null. Own-IP set first, then non-routable classes.
    param(
        [Parameter(Mandatory)] [string]$Ip,
        [Parameter(Mandatory)] [string[]]$Exclusions
    )
    # compare canonical forms: '::ffff:<own>' or a decimal spelling of the own
    # IP must not slip past a raw string match; transition addresses
    # (NAT64/6to4/IPv4-compatible) are judged by their embedded IPv4 too
    $canon = ConvertTo-CanonicalIp -Ip $Ip
    if (-not $canon) { return 'invalid' }
    $own = @($Exclusions | ForEach-Object { ConvertTo-CanonicalIp -Ip $_ } | Where-Object { $_ })
    if ($canon -in $own) { return 'own public ip' }
    $embedded = Get-EmbeddedIPv4 -Ip $canon
    if ($embedded -and $embedded -in $own) { return 'own public ip' }
    $reason = Test-NonRoutableIp -Ip $canon
    if (-not $reason -and $embedded) { $reason = Test-NonRoutableIp -Ip $embedded }
    return $reason
}

function Get-CymruAsn {
    # Team Cymru IP->ASN via DNS TXT. Returns @{asn; as_name; as_country} or
    # $null (lookup problems are context loss, never fatal). $ResolveFn
    # (name -> first TXT string) injectable for tests.
    param(
        [Parameter(Mandatory)] [string]$Ip,
        [scriptblock]$ResolveFn
    )
    if (-not $ResolveFn) {
        $ResolveFn = {
            param($name)
            $r = Resolve-DnsName -Name $name -Type TXT -QuickTimeout -ErrorAction Stop
            return @($r | Where-Object { $_.PSObject.Properties['Strings'] } | ForEach-Object { $_.Strings })[0]
        }
    }
    try {
        $qname = ConvertTo-CymruName -Ip $Ip
        if (-not $qname) { return $null }
        $txt = & $ResolveFn $qname
        if (-not $txt) { return $null }
        # "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
        $parts = $txt.Split('|').ForEach{ $_.Trim() }
        $asn = [int]($parts[0].Split(' ')[0])   # multi-origin: first ASN
        $country = $parts[2]
        $asName = $null
        try {
            $nameTxt = & $ResolveFn "AS$asn.asn.cymru.com"
            if ($nameTxt) { $asName = $nameTxt.Split('|')[-1].Trim() }
        }
        catch {}
        return @{ asn = $asn; as_name = $asName; as_country = $country }
    }
    catch {
        return $null
    }
}

Export-ModuleMember -Function Update-OwnIp, Get-OwnIpExclusions,
    Test-ExcludedFromLookup, Get-CymruAsn
