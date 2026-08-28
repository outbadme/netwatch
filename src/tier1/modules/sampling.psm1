# sampling.psm1 - Get-NetTCPConnection snapshots normalized for classify.psm1.
# PID -> process info resolved once per PID via CIM Win32_Process and cached
# (image_exists re-checked every sample: F14 drop-run-delete detection).

Set-StrictMode -Version Latest

function Get-ListenPorts {
    # Set of locally-listening TCP ports (inbound-direction heuristic input).
    $set = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($l in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $null = $set.Add([int]$l.LocalPort)
    }
    return , $set
}

function Get-ConnDirection {
    # Heuristic per ARCHITECTURE 3.1: a connection whose local port is in the
    # host's Listen table was accepted, not initiated -> inbound.
    param(
        [Parameter(Mandatory)] [int]$LocalPort,
        [Parameter(Mandatory)] $ListenPorts
    )
    if ($ListenPorts.Contains($LocalPort)) { return 'inbound' }
    return 'outbound'
}

function Resolve-ProcessInfo {
    # name (lowercase, no .exe) / image_path / command_line / image_exists for
    # a PID; CIM query once per PID lifetime, cached in $PidCache.
    param(
        [Parameter(Mandatory)] [int]$ProcessId,
        [Parameter(Mandatory)] [hashtable]$PidCache
    )
    if ($PidCache.ContainsKey($ProcessId)) {
        $info = $PidCache[$ProcessId]
    }
    else {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
        if ($p) {
            $info = @{
                name         = ($p.Name -replace '\.exe$', '').ToLowerInvariant()
                image_path   = $p.ExecutablePath
                command_line = [string]$p.CommandLine
            }
        }
        else {
            $info = @{ name = 'unknown'; image_path = $null; command_line = '' }
        }
        $PidCache[$ProcessId] = $info
    }
    # existence re-checked every call: deleted-image processes must flip this
    $exists = $false
    if ($info.image_path) { $exists = Test-Path -LiteralPath $info.image_path -PathType Leaf }
    return @{
        name         = $info.name
        image_path   = $info.image_path
        command_line = $info.command_line
        image_exists = $exists
    }
}

function Get-ConnectionSample {
    # Normalized snapshot of Established/SynSent TCP connections.
    param(
        [Parameter(Mandatory)] [hashtable]$PidCache,
        $ListenPorts
    )
    if ($null -eq $ListenPorts) { $ListenPorts = Get-ListenPorts }
    $conns = @(Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue)
    $result = foreach ($c in $conns) {
        $ownPid = [int]$c.OwningProcess
        $info = Resolve-ProcessInfo -ProcessId $ownPid -PidCache $PidCache
        @{
            pid                = $ownPid
            name               = $info.name
            image_path         = $info.image_path
            image_exists       = $info.image_exists
            command_line       = $info.command_line
            laddr              = [string]$c.LocalAddress
            lport              = [int]$c.LocalPort
            raddr              = [string]$c.RemoteAddress
            rport              = [int]$c.RemotePort
            state              = [string]$c.State
            direction          = (Get-ConnDirection -LocalPort ([int]$c.LocalPort) -ListenPorts $ListenPorts)
            domain             = $null            # filled by attribution
            attribution_source = 'none'
        }
    }
    return @($result)
}

function Sync-PidCache {
    # Drops cache entries for PIDs no longer owning any sampled connection.
    # Windows reuses PIDs within hours; without this a new (possibly hostile)
    # process inheriting a cached PID would be classified under the OLD
    # process identity - a false "whitelisted" (review finding). A PID that
    # reappears later is simply re-resolved via CIM.
    param(
        [Parameter(Mandatory)] [hashtable]$PidCache,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [int[]]$ActivePids
    )
    $active = [System.Collections.Generic.HashSet[int]]::new([int[]]$ActivePids)
    foreach ($cachedPid in @($PidCache.Keys)) {
        if (-not $active.Contains($cachedPid)) { $PidCache.Remove($cachedPid) }
    }
}

function Get-HostAddresses {
    # All IP addresses assigned to this host's interfaces. A remote endpoint
    # in this set means both ends are this machine ("both ends local" noise
    # per ARCHITECTURE 3.1(5)) - distinct from OTHER private/tailnet peers,
    # which must stay escalatable.
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @(Get-NetIPAddress -ErrorAction SilentlyContinue)) {
        if ($a.IPAddress) { $null = $set.Add(($a.IPAddress -replace '%\d+$', '')) }   # strip zone index
    }
    return , $set
}

function Test-ImageGone {
    # F14: process whose recorded image file vanished from disk (classic
    # drop-run-delete). Only claimable when a path was recorded.
    param([Parameter(Mandatory)] $Conn)
    if (-not $Conn.image_path) { return $false }
    return -not (Test-Path -LiteralPath $Conn.image_path -PathType Leaf)
}

Export-ModuleMember -Function Get-ListenPorts, Get-ConnDirection,
    Resolve-ProcessInfo, Get-ConnectionSample, Test-ImageGone, Sync-PidCache,
    Get-HostAddresses
