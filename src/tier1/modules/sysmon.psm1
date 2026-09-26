# sysmon.psm1 - Sysmon NetworkConnect (event 3) as a second connection source.
# Get-NetTCPConnection is a 30-s poll: a connection opened and closed between
# two ticks (short beacons, one-shot exfil) is never seen. Sysmon logs every
# TCP connect with the process image, so draining its channel each tick fills
# that gap. Same bookmarked-reader pattern as dnsetw.psm1 (EventRecordID
# persisted in state\sysmon-bookmark.xml).
#
# Optional: Sysmon is operator-installed (install/enable-sysmon.ps1 with
# config/sysmon-netwatch.xml). Channel missing/unreadable => health
# 'unavailable', polling continues exactly as before (never fatal).
#
# Field semantics (Sysmon event 3): Initiated=true -> this host opened the
# connection: Source* is local, Destination* is remote. Initiated=false ->
# accepted inbound: Source* is the remote peer, Destination* is local.

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'state.psm1')
Import-Module (Join-Path $PSScriptRoot 'netutil.psm1')

$script:ChannelName = 'Microsoft-Windows-Sysmon/Operational'
$script:MaxEventsPerTick = 5000     # runaway guard; the rest is drained next tick

function Test-SysmonAvailable {
    # 'ok' when the channel exists, is enabled AND this process can read it
    # (Sysmon's channel ACL can exclude non-elevated users); else 'unavailable'.
    try {
        $cfg = [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new($script:ChannelName)
        if (-not $cfg.IsEnabled) { return 'unavailable' }
        $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $script:ChannelName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*[System[EventID=3]]')
        $q.ReverseDirection = $true
        $r = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
        try { $ev = $r.ReadEvent(); if ($ev) { $ev.Dispose() } }
        finally { $r.Dispose() }
        return 'ok'
    }
    catch { return 'unavailable' }
}

function ConvertFrom-SysmonNetEventXml {
    # One event-3 XML -> Conn hashtable in sampling.psm1's shape (plus
    # record_id / utc), or $null for non-TCP / malformed events.
    param([Parameter(Mandatory)] [string]$Xml)
    $doc = [xml]$Xml
    $data = @{}
    foreach ($d in @($doc.Event.EventData.Data)) {
        $n = $d.PSObject.Properties['Name']?.Value
        if ($n) { $data[$n] = [string]$d.PSObject.Properties['#text']?.Value }
    }
    if ($data['Protocol'] -ne 'tcp') { return $null }
    $initiated = $data['Initiated'] -eq 'true'
    $local  = if ($initiated) { 'Source' } else { 'Destination' }
    $remote = if ($initiated) { 'Destination' } else { 'Source' }
    $raddr = ConvertTo-CanonicalIp -Ip $data["${remote}Ip"]
    $laddr = ConvertTo-CanonicalIp -Ip $data["${local}Ip"]
    $rport = 0; $lport = 0; $procId = 0
    if (-not $raddr -or -not $laddr -or
        -not [int]::TryParse($data["${remote}Port"], [ref]$rport) -or
        -not [int]::TryParse($data["${local}Port"], [ref]$lport) -or
        -not [int]::TryParse($data['ProcessId'], [ref]$procId)) { return $null }
    $image = $data['Image']
    $name = if ($image) { ([IO.Path]::GetFileName($image.Replace('\', '/')) -replace '\.exe$', '').ToLowerInvariant() } else { 'unknown' }
    return @{
        record_id          = [long]$doc.Event.System.EventRecordID
        pid                = $procId
        name               = $name
        image_path         = if ($image) { $image } else { $null }
        image_exists       = $false          # filled by the caller (file system check)
        command_line       = ''
        laddr              = $laddr
        lport              = $lport
        raddr              = $raddr
        rport              = $rport
        state              = 'sysmon'        # seen via event, not in the live table
        direction          = if ($initiated) { 'outbound' } else { 'inbound' }
        domain             = $null
        attribution_source = 'none'
    }
}

function Get-SysmonBookmark {
    param([Parameter(Mandatory)] $Config)
    $file = Join-Path $Config.paths.state_root 'state\sysmon-bookmark.xml'
    if (-not (Test-Path -LiteralPath $file)) { return $null }      # first run: start at "now"
    try { return [long]([xml](Get-Content -LiteralPath $file -Raw)).bookmark.record }
    catch {
        Write-OpLog -Config $Config -Level WARN -Message 'sysmon bookmark corrupt, restarting at the newest event'
        return $null
    }
}

function Set-SysmonBookmark {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [long]$RecordId)
    $file = Join-Path $Config.paths.state_root 'state\sysmon-bookmark.xml'
    "<bookmark record=""$RecordId"" />" | Set-Content -LiteralPath $file -Encoding utf8
}

function Read-SysmonConnections {
    # Drains event-3 records newer than the bookmark -> Conn hashtables. On
    # the very first run (no bookmark) it only records the newest id: history
    # from before netwatch ran is not replayed as a burst of escalations.
    param([Parameter(Mandatory)] $Config)
    $conns = [System.Collections.Generic.List[object]]::new()
    try {
        $last = Get-SysmonBookmark -Config $Config
        if ($null -eq $last) {
            $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
                $script:ChannelName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
            $q.ReverseDirection = $true
            $r = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
            try {
                $ev = $r.ReadEvent()
                $newest = if ($ev) { [long]$ev.RecordId } else { [long]0 }
                if ($ev) { $ev.Dispose() }
            }
            finally { $r.Dispose() }
            Set-SysmonBookmark -Config $Config -RecordId $newest
            return @()
        }
        $xpath = "*[System[EventID=3 and EventRecordID > $last]]"
        $q = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $script:ChannelName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($q)
        try {
            $maxId = $last
            $n = 0
            while ($n -lt $script:MaxEventsPerTick) {
                $ev = $reader.ReadEvent()
                if ($null -eq $ev) { break }
                $n++
                try {
                    if ([long]$ev.RecordId -gt $maxId) { $maxId = [long]$ev.RecordId }
                    $c = ConvertFrom-SysmonNetEventXml -Xml $ev.ToXml()
                    if ($c) { $conns.Add($c) }
                }
                finally { $ev.Dispose() }
            }
            if ($n -ge $script:MaxEventsPerTick) {
                Write-OpLog -Config $Config -Level WARN -Message "sysmon: $n events this tick (cap) - remainder next tick"
            }
            if ($maxId -gt $last) { Set-SysmonBookmark -Config $Config -RecordId $maxId }
        }
        finally { $reader.Dispose() }
    }
    catch {
        Write-OpLog -Config $Config -Level TRACE -Message "sysmon read failed: $($_.Exception.Message)"
    }
    return @($conns)
}

function Merge-SysmonConnections {
    # Adds event-only connections (not in the live table any more - the
    # short-lived ones this source exists for) to the sample. Live-table
    # entries win: they carry the current state and the CIM command line.
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Sample,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Events
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($c in $Sample) { $null = $seen.Add("$($c.pid)|$($c.raddr)|$($c.rport)") }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $Sample) { $out.Add($c) }
    foreach ($e in $Events) {
        $k = "$($e.pid)|$($e.raddr)|$($e.rport)"
        if (-not $seen.Add($k)) { continue }                 # already live, or a repeat event
        $e.Remove('record_id')
        if ($e.image_path) { $e.image_exists = Test-Path -LiteralPath $e.image_path -PathType Leaf }
        $out.Add($e)
    }
    return @($out)
}

Export-ModuleMember -Function Test-SysmonAvailable, ConvertFrom-SysmonNetEventXml,
    Read-SysmonConnections, Merge-SysmonConnections
