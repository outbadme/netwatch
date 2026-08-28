# snicapture.tests.ps1 - tshark line parsing, SNI cache, supervisor backoff
# (F4). Uses tests/stubs/fake-tshark.cmd as the capture child.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\snicapture.psm1" -Force

# --- line parser -------------------------------------------------------------
$e = ConvertFrom-TsharkLine -Line "104.18.20.246`t`t443`tapi.kimi.com"
Assert-Equal '104.18.20.246' $e.ip 'v4 dst parsed'
Assert-Equal 443 $e.port 'port parsed'
Assert-Equal 'api.kimi.com' $e.domain 'sni parsed'
Assert-Equal 'sni' $e.source 'tls line carries source sni'

$e = ConvertFrom-TsharkLine -Line "`t2606:4700::6812:14f6`t443`tv6.example.net"
Assert-Equal '2606:4700::6812:14f6' $e.ip 'v6 dst parsed when v4 empty'

Assert-Null (ConvertFrom-TsharkLine -Line "1.2.3.4`t`t443`t") 'no sni and no host skipped'
Assert-Null (ConvertFrom-TsharkLine -Line '') 'empty line skipped'
Assert-Null (ConvertFrom-TsharkLine -Line "garbage") 'malformed line skipped'

# 5-field lines: http.host is the LAST field (port-80 CRL class, live alarm
# 20260827-143918: lsass -> 104.18.20/21.213:80 = Let's Encrypt CRL)
$e = ConvertFrom-TsharkLine -Line "104.18.21.213`t`t80`t`tyr1.c.lencr.org"
Assert-Equal 80 $e.port 'port 80 parsed'
Assert-Equal 'yr1.c.lencr.org' $e.domain 'http host parsed'
Assert-Equal 'http-host' $e.source 'plaintext host carries source http-host'

$e = ConvertFrom-TsharkLine -Line "1.2.3.4`t`t443`ttls.example.com`t"
Assert-Equal 'sni' $e.source 'sni with empty host stays sni'
Assert-Equal 'tls.example.com' $e.domain 'sni domain kept'

$e = ConvertFrom-TsharkLine -Line "1.2.3.4`t`t443`ttls.example.com`thost.example.com"
Assert-Equal 'sni' $e.source 'sni preferred when both present'

$e = ConvertFrom-TsharkLine -Line "1.2.3.4`t`t80`t`tExample.COM:8080"
Assert-Equal 'example.com' $e.domain 'host normalized, explicit :port stripped'
Assert-Null (ConvertFrom-TsharkLine -Line "1.2.3.4`t`t80`t`t10.0.0.5") 'ip-literal host attributes nothing'

# --- interface selection -----------------------------------------------------
# Regression: with no -i tshark binds the first enumerated adapter (a WAN
# miniport here), capturing nothing while still reporting healthy.
$ifs = Get-SniInterface -Config ([pscustomobject]@{ sni = [pscustomobject]@{ interfaces = @('nic-a', 'nic-b') } })
Assert-Equal 2 @($ifs).Count 'configured interfaces win'
Assert-Equal 'nic-a' @($ifs)[0] 'configured interface name preserved'

$ifs = Get-SniInterface -Config ([pscustomobject]@{ sni = [pscustomobject]@{ interfaces = @() } })
Assert-True (@($ifs) -notcontains $null) 'auto-detect returns a clean name list'

$ifs = Get-SniInterface -Config ([pscustomobject]@{ sni = [pscustomobject]@{ capture_ports = @(443) } })
Assert-NotNull $ifs 'missing interfaces key falls back to auto-detect, no throw'

# --- cache + attribution -----------------------------------------------------
$caches = @{ sni = @{} }
$now = [datetime]::UtcNow
Update-SniCache -Caches $caches -Entry (ConvertFrom-TsharkLine -Line "104.18.20.246`t`t443`tapi.kimi.com") -NowUtc $now
$att = Resolve-SniAttribution -Caches $caches -Conn @{ raddr = '104.18.20.246'; rport = 443 }
Assert-Equal 'sni' $att.source 'sni attribution source'
Assert-Equal 'api.kimi.com' $att.domain 'sni domain'
$att = Resolve-SniAttribution -Caches $caches -Conn @{ raddr = '104.18.20.246'; rport = 8443 }
Assert-Null $att 'different port not attributed'

# http-host entries resolve with their own (weaker) source, never as 'sni'
Update-SniCache -Caches $caches -Entry (ConvertFrom-TsharkLine -Line "104.18.21.213`t`t80`t`tyr1.c.lencr.org") -NowUtc $now
$att = Resolve-SniAttribution -Caches $caches -Conn @{ raddr = '104.18.21.213'; rport = 80 }
Assert-Equal 'http-host' $att.source 'http-host attribution source'
Assert-Equal 'yr1.c.lencr.org' $att.domain 'http-host domain'

# --- supervisor with the fake child -----------------------------------------
$root = New-TestStateRoot
try {
    $stubPath = Join-Path $PSScriptRoot 'stubs\fake-tshark.cmd'
    $cfgPath = New-TestConfig -StateRoot $root -Override @{
        sni = @{
            tshark_exe                   = $stubPath
            capture_ports                = @(443, 8443)
            restart_backoff_sec          = @(0, 0, 0)
            max_restarts_before_degraded = 2
        }
    }
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg

    $state = New-SniState
    $env:FAKE_TSHARK_ARGS = Join-Path $root 'tshark-args.txt'
    Start-SniCapture -Config $cfg -State $state
    Assert-Equal 'ok' $state.health 'capture started ok'
    Start-Sleep -Milliseconds 800   # let the stub emit + exit

    # invocation contract: http ports in the capture filter, http.request in
    # the display filter, http.host as the LAST extracted field (a green
    # parser means nothing if tshark is never asked for the field)
    $tsharkArgs = Get-Content $env:FAKE_TSHARK_ARGS -Raw
    Remove-Item Env:FAKE_TSHARK_ARGS
    Assert-True ($tsharkArgs -match 'tcp port 80') 'http port in capture filter'
    Assert-True ($tsharkArgs -match 'http\.request') 'http.request in display filter'
    Assert-True ($tsharkArgs -match 'tls\.handshake\.type==1 or http\.request') 'combined display filter'
    Assert-True ($tsharkArgs.TrimEnd() -match 'http\.host\s*$') 'http.host is the last extracted field'

    Read-SniLines -State $state -Caches $caches -NowUtc ([datetime]::UtcNow)
    $att = Resolve-SniAttribution -Caches $caches -Conn @{ raddr = '2606:4700::6812:14f6'; rport = 443 }
    Assert-NotNull $att 'line from child landed in cache'
    Assert-Equal 'v6.example.net' $att.domain 'v6 sni domain from child'
    $att = Resolve-SniAttribution -Caches $caches -Conn @{ raddr = '104.18.21.213'; rport = 80 }
    Assert-NotNull $att 'http line from child landed in cache'
    Assert-Equal 'http-host' $att.source 'child http line resolves as http-host'

    # child is dead now; health ticks: delay is scheduled BEFORE each restart
    # (F4 order), then restarts accumulate until degraded
    $h = $state.health
    for ($i = 0; $i -lt 12 -and $h -ne 'degraded'; $i++) {
        $h = Test-SniHealth -Config $cfg -State $state -NowUtc ([datetime]::UtcNow)
        Start-Sleep -Milliseconds 250
    }
    Assert-True ($state.restarts -ge 2) "restarts counted (got $($state.restarts))"
    Assert-Equal 'degraded' $h 'degraded after max restarts (F4)'
    Stop-SniCapture -State $state

    # --- alive-but-blind child is degraded, not 'ok' -------------------------
    # The 2026-08-27 root cause: tshark bound to an adapter with no traffic ran
    # healthy and silent for hours while attribution stayed empty.
    $cfgBlindPath = New-TestConfig -StateRoot $root -Override @{ sni = @{ blind_after_sec = 60 } }
    $cfgBlind = Get-NetwatchConfig -Path $cfgBlindPath
    $bs = New-SniState
    $bs.proc       = Get-Process -Id $PID      # any live process; only HasExited is read
    $bs.health     = 'ok'
    $bs.started_at = [datetime]::UtcNow.AddSeconds(-300)
    $bs.lines_seen = 0

    Assert-Equal 'degraded' (Test-SniHealth -Config $cfgBlind -State $bs -NowUtc ([datetime]::UtcNow)) `
        'live child with zero lines past the threshold is degraded'
    Assert-True $bs.blind_warned 'blindness warned once'

    $bs.lines_seen = 7                          # capture starts producing
    $bs.last_line_at = [datetime]::UtcNow       # (Read-SniLines stamps this)
    Assert-Equal 'ok' (Test-SniHealth -Config $cfgBlind -State $bs -NowUtc ([datetime]::UtcNow)) `
        'health recovers once lines flow'
    Assert-False $bs.blind_warned 'warn latch cleared on recovery'

    # LATE blindness (the live scenario: VPN comes up mid-day and hides TLS
    # from the adapter): lines flowed earlier, then silence past the threshold
    $bsLate = New-SniState
    $bsLate.proc = Get-Process -Id $PID; $bsLate.health = 'ok'
    $bsLate.started_at   = [datetime]::UtcNow.AddHours(-2)
    $bsLate.lines_seen   = 50
    $bsLate.last_line_at = [datetime]::UtcNow.AddSeconds(-300)
    Assert-Equal 'degraded' (Test-SniHealth -Config $cfgBlind -State $bsLate -NowUtc ([datetime]::UtcNow)) `
        'capture that went silent after producing lines is degraded too'

    # a young child is not judged blind yet
    $bs2 = New-SniState
    $bs2.proc = Get-Process -Id $PID; $bs2.health = 'ok'
    $bs2.started_at = [datetime]::UtcNow; $bs2.lines_seen = 0
    Assert-Equal 'ok' (Test-SniHealth -Config $cfgBlind -State $bs2 -NowUtc ([datetime]::UtcNow)) `
        'child inside the grace window stays ok'

    # blind_after_sec = 0 disables the check entirely
    $bs3 = New-SniState
    $bs3.proc = Get-Process -Id $PID; $bs3.health = 'ok'
    $bs3.started_at = [datetime]::UtcNow.AddSeconds(-9999); $bs3.lines_seen = 0
    Assert-Equal 'ok' (Test-SniHealth -Config $cfg -State $bs3 -NowUtc ([datetime]::UtcNow)) `
        'blind_after_sec=0 disables blindness detection'

    # --- egress change: interface set re-detected on the fly -----------------
    # Task 2026-08-28: Get-SniInterface was computed ONCE at Start; a VPN
    # coming up later left tshark on stale adapters (measured 27.08: the DCO
    # adapter carried 220 of 239 TLS/443 packets). Sets are compared
    # order-insensitively, flapping is debounced, an intentional rebind never
    # touches the `restarts` crash counter.
    $cfgDiff = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root -Override @{
        sni = @{ tshark_exe = $stubPath; interfaces = @('nic-b'); interface_settle_sec = 60 } })
    $cfgSame = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root -Override @{
        sni = @{ tshark_exe = $stubPath; interfaces = @('nic-a'); interface_settle_sec = 60 } })
    $es = New-SniState
    $es.proc = Get-Process -Id $PID; $es.health = 'ok'
    $es.started_at = [datetime]::UtcNow; $es.interfaces = @('nic-a')
    $tE = [datetime]::UtcNow
    $null = Test-SniHealth -Config $cfgDiff -State $es -NowUtc $tE
    Assert-Equal 'nic-a' @($es.interfaces)[0] 'first sighting of a new set is debounced'
    Assert-Equal 0 $es.restarts 'crash counter untouched by sighting'
    $null = Test-SniHealth -Config $cfgDiff -State $es -NowUtc $tE.AddSeconds(30)
    Assert-Equal 'nic-a' @($es.interfaces)[0] 'still the old set inside the settle window'
    $h = Test-SniHealth -Config $cfgDiff -State $es -NowUtc $tE.AddSeconds(61)
    Assert-Equal 'nic-b' @($es.interfaces)[0] 'capture rebound to the new set after settle'
    Assert-Equal 0 $es.restarts 'intentional rebind NOT counted as a restart'
    Assert-Equal 'ok' $h 'health ok after rebind'
    Assert-NotNull $es.last_change 'change recorded (packet notes need it)'
    Assert-Equal 'nic-a' @($es.last_change.old)[0] 'old set recorded'
    Assert-Equal 'nic-b' @($es.last_change.new)[0] 'new set recorded'
    Stop-SniCapture -State $es

    # flap: the new set reverts before settle -> candidate reset, no rebind
    $es2 = New-SniState
    $es2.proc = Get-Process -Id $PID; $es2.health = 'ok'
    $es2.started_at = [datetime]::UtcNow; $es2.interfaces = @('nic-a')
    $null = Test-SniHealth -Config $cfgDiff -State $es2 -NowUtc $tE
    $null = Test-SniHealth -Config $cfgSame -State $es2 -NowUtc $tE.AddSeconds(30)   # reverted
    $null = Test-SniHealth -Config $cfgDiff -State $es2 -NowUtc $tE.AddSeconds(70)   # fresh candidate
    Assert-Equal 'nic-a' @($es2.interfaces)[0] 'flap does not rebind (settle restarts on revert)'
    Assert-Equal 0 $es2.restarts 'no restarts from flapping'

    # order-insensitive: same members, different order = same set
    $cfgOrder = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root -Override @{
        sni = @{ tshark_exe = $stubPath; interfaces = @('nic-b', 'nic-a'); interface_settle_sec = 60 } })
    $es3 = New-SniState
    $es3.proc = Get-Process -Id $PID; $es3.health = 'ok'
    $es3.started_at = [datetime]::UtcNow; $es3.interfaces = @('nic-a', 'nic-b')
    $null = Test-SniHealth -Config $cfgOrder -State $es3 -NowUtc $tE
    $null = Test-SniHealth -Config $cfgOrder -State $es3 -NowUtc $tE.AddSeconds(120)
    Assert-Equal 2 @($es3.interfaces).Count 'order difference is not a change'
    Assert-Null $es3.last_change 'no change recorded for reordered set'

    # --- missing exe: unavailable immediately, no throw ----------------------
    $cfgPath2 = New-TestConfig -StateRoot $root   # default tshark_exe = nonexistent
    $cfg2 = Get-NetwatchConfig -Path $cfgPath2
    $state2 = New-SniState
    Start-SniCapture -Config $cfg2 -State $state2
    Assert-Equal 'unavailable' $state2.health 'missing tshark = unavailable (F4)'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
