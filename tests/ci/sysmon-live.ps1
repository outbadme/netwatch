# sysmon-live.ps1 - CI-only (Windows runner, admin): installs the real Sysmon
# through install/enable-sysmon.ps1 with config/sysmon-netwatch.xml and
# checks the whole path end to end: signer/version gate, channel enabled,
# TCP connects logged with the right image and direction, UDP and loopback
# NOT logged, and sysmon.psm1 turning events into connections.
# Not a *.tests.ps1 file: it installs a driver, so run-tests.ps1 never
# picks it up on a developer machine.
param([Parameter(Mandatory)] [string]$SysmonExe)
. "$PSScriptRoot\..\_assert.ps1"
. "$PSScriptRoot\..\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\..\src\tier1\modules\sysmon.psm1" -Force

$pwshExe = (Get-Process -Id $PID).Path
& $pwshExe -NoProfile -File "$PSScriptRoot\..\..\install\enable-sysmon.ps1" -SysmonExe $SysmonExe
Assert-Equal 0 $LASTEXITCODE 'enable-sysmon.ps1 installs Sysmon with the netwatch config'
& $pwshExe -NoProfile -File "$PSScriptRoot\..\..\install\enable-sysmon.ps1" -SysmonExe $SysmonExe 2>$null
Assert-True ($LASTEXITCODE -ne 0) 'second run without -Keep/-ReplaceExistingConfig refuses'

$root = New-TestStateRoot
try {
    $cfg = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root)
    Initialize-StateRoot -Config $cfg
    $null = Read-SysmonConnections -Config $cfg          # first call: bookmark at "now"

    # traffic: one TCP connect out, one UDP datagram out, one loopback TCP
    $tcp = [Net.Sockets.TcpClient]::new()
    $tcp.Connect('1.1.1.1', 443); $tcpLocal = $tcp.Client.LocalEndPoint.Port; $tcp.Dispose()
    $udp = [Net.Sockets.UdpClient]::new()
    $null = $udp.Send([byte[]](1, 2, 3), 3, '9.9.9.9', 53); $udp.Dispose()
    $lsn = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $lsn.Start()
    $lc = [Net.Sockets.TcpClient]::new(); $lc.Connect('127.0.0.1', $lsn.LocalEndpoint.Port); $lc.Dispose(); $lsn.Stop()

    $mine = @()
    for ($i = 0; $i -lt 20 -and -not $mine; $i++) {
        Start-Sleep -Seconds 1
        $mine = @(Read-SysmonConnections -Config $cfg | Where-Object { $_.pid -eq $PID })
    }
    Assert-Equal 'ok' (Test-SysmonAvailable) 'health ok once an event 3 exists'
    $out = @($mine | Where-Object { $_.raddr -eq '1.1.1.1' -and $_.rport -eq 443 })
    Assert-Equal 1 $out.Count 'TCP connect to 1.1.1.1:443 read back as one connection'
    Assert-Equal 'outbound' $out[0].direction 'Initiated=true -> outbound'
    Assert-Equal $tcpLocal $out[0].lport 'local port matches the socket'
    Assert-True ($out[0].image_path -ieq $pwshExe) "image is this pwsh ($($out[0].image_path))"
    Assert-Equal 0 @($mine | Where-Object { $_.raddr -in '127.0.0.1', '::1' }).Count 'loopback excluded by the config'

    # UDP: sysmon.psm1 drops it anyway, so ask the channel itself
    $since = [datetime]::UtcNow.AddMinutes(-2).ToString('o')
    $udpEv = @(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3 and TimeCreated[@SystemTime>='$since']]]" -ErrorAction SilentlyContinue |
        Where-Object { $_.ToXml() -match "<Data Name='Protocol'>udp</Data>" -and $_.ToXml() -match "<Data Name='ProcessId'>$PID</Data>" })
    Assert-Equal 0 $udpEv.Count 'UDP not logged (TCP-only include)'
}
finally { Remove-TestStateRoot $root }
Complete-Tests
