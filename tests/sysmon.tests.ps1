# sysmon.tests.ps1 - Sysmon NetworkConnect (event 3) source: event parsing,
# merge with the polled sample, packet health flag, and the end-to-end case
# it exists for (a short-lived impostor connection invisible to polling).
# Platform-neutral: events are fed as XML; the live channel is only probed
# for "does not crash when absent".
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\classify.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\escalate.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\sysmon.psm1" -Force

function New-SysmonXml {
    param([hashtable]$D, [long]$Rec = 100)
    $fields = [ordered]@{
        UtcTime = '2026-09-26 10:00:00.000'; ProcessGuid = '{00000000-0000-0000-0000-000000000000}'
        ProcessId = '4321'; Image = 'C:\Users\victim\AppData\Local\Temp\svchost.exe'; User = 'PC\victim'
        Protocol = 'tcp'; Initiated = 'true'; SourceIsIpv6 = 'false'; SourceIp = '192.168.1.10'
        SourceHostname = '-'; SourcePort = '50123'; SourcePortName = '-'; DestinationIsIpv6 = 'false'
        DestinationIp = '203.0.113.77'; DestinationHostname = '-'; DestinationPort = '443'; DestinationPortName = 'https'
    }
    foreach ($k in $D.Keys) { $fields[$k] = $D[$k] }
    $data = ($fields.GetEnumerator() | ForEach-Object {
            "<Data Name='$($_.Key)'>$([Security.SecurityElement]::Escape([string]$_.Value))</Data>" }) -join ''
    return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" +
           "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>3</EventID><EventRecordID>$Rec</EventRecordID>" +
           "</System><EventData>$data</EventData></Event>"
}

# --- parsing -------------------------------------------------------------------
$c = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{})
Assert-NotNull $c 'tcp event parsed'
Assert-Equal 100 $c.record_id 'record id'
Assert-Equal 4321 $c.pid 'pid'
Assert-Equal 'svchost' $c.name 'name from Image basename, lowercase, no .exe'
Assert-Equal 'C:\Users\victim\AppData\Local\Temp\svchost.exe' $c.image_path 'image path kept'
Assert-Equal 'outbound' $c.direction 'Initiated=true -> outbound'
Assert-Equal '203.0.113.77' $c.raddr 'outbound: remote = Destination'
Assert-Equal 443 $c.rport 'outbound: remote port = DestinationPort'
Assert-Equal '192.168.1.10' $c.laddr 'outbound: local = Source'
Assert-Equal 'sysmon' $c.state 'state marks the event source'

$c = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{
        Initiated = 'false'; SourceIp = '100.64.0.21'; SourcePort = '55000'
        DestinationIp = '192.168.1.10'; DestinationPort = '3389'; Image = 'C:\Windows\System32\svchost.exe' })
Assert-Equal 'inbound' $c.direction 'Initiated=false -> inbound'
Assert-Equal '100.64.0.21' $c.raddr 'inbound: remote = Source'
Assert-Equal 3389 $c.lport 'inbound: local port = DestinationPort'

$c = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ DestinationIp = '::ffff:203.0.113.78'; DestinationIsIpv6 = 'true' })
Assert-Equal '203.0.113.78' $c.raddr 'v4-mapped destination canonicalized'
Assert-Null (ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ Protocol = 'udp' })) 'udp ignored (tier 1 is TCP-only)'
Assert-Null (ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ DestinationPort = '' })) 'missing port -> dropped'
Assert-Null (ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ DestinationIp = 'garbage' })) 'bad ip -> dropped'

# --- merge with the polled sample -----------------------------------------------
$live = @{ pid = 10; name = 'claude'; image_path = $null; image_exists = $true; command_line = 'claude -p'
           laddr = '192.168.1.10'; lport = 50000; raddr = '160.79.104.10'; rport = 443; state = 'Established'
           direction = 'outbound'; domain = $null; attribution_source = 'none' }
$evLive  = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ ProcessId = '10'; DestinationIp = '160.79.104.10'; Image = 'C:\x\claude.exe' } 1)
$evShort = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{} 2)
$evDup   = ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{} 3)
$merged = @(Merge-SysmonConnections -Sample @($live) -Events @($evLive, $evShort, $evDup))
Assert-Equal 2 $merged.Count 'live conn kept once, short-lived added once'
Assert-Equal 'claude -p' $merged[0].command_line 'live-table entry wins over its event'
Assert-Equal 'sysmon' $merged[1].state 'event-only conn appended'
Assert-False $merged[1].ContainsKey('record_id') 'record_id stripped from merged conns'
Assert-False $merged[1].image_exists 'image existence checked on disk (absent here)'
$merged = @(Merge-SysmonConnections -Sample @() -Events @())
Assert-Equal 0 $merged.Count 'empty merge'

# --- live channel absent: no crash, no events --------------------------------------
$root = New-TestStateRoot
try {
    $cfg = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root)
    Initialize-StateRoot -Config $cfg
    # no Sysmon here (Linux, or a Windows machine/runner without the service)
    $sysmonSvc = if ($IsWindows) { Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue } else { $null }
    if (-not $sysmonSvc) {
        Assert-Equal 'unavailable' (Test-SysmonAvailable) 'no Sysmon channel -> unavailable'
        Assert-Equal 0 @(Read-SysmonConnections -Config $cfg).Count 'reader returns nothing, does not throw'
    }
    else { Write-Host "INFO: Sysmon installed here - live health: $(Test-SysmonAvailable)" }

    # --- end to end: short-lived impostor seen only by Sysmon -------------------
    # svchost name + Temp image: identity mismatch -> residual (not the 7680
    # whitelist entry), and the packet says Sysmon was on
    $wl = Get-Whitelist -Config $cfg
    $imp = @(Merge-SysmonConnections -Sample @() -Events @(
            (ConvertFrom-SysmonNetEventXml -Xml (New-SysmonXml @{ DestinationPort = '7680' } 7))))[0]
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $imp -Config $cfg) 'sysmon-only impostor svchost:7680 is residual'
    $queue = @{}
    $now = [datetime]::UtcNow
    $k = Update-ResidualQueue -Queue $queue -Conn $imp -NowUtc $now
    $pkt = Build-EscalationPacket -Keys @($k) -Queue $queue -Config $cfg `
        -Health @{ sni_capture = 'ok'; dns_etw = 'ok'; sysmon = 'ok' } -NowUtc $now
    Assert-Equal 'ok' $pkt.collector_health.sysmon 'packet carries sysmon health (schema-valid)'
    Assert-Equal 'sysmon' $pkt.connections[0].state_history[0] 'state history shows the event source'
    Assert-Equal 'mismatch' $pkt.connections[0].process.identity 'identity from the Sysmon image path'
}
finally { Remove-TestStateRoot $root }

Complete-Tests
