# tier2guards.tests.ps1 - input guards of the Tier-2 tool backends that must
# hold against alternate spellings (review findings 2026-09-25):
#  - check-reputation: canonical IP before every guard and in the lookup URL
#    (v4-mapped / decimal / NAT64 / 6to4 own-IP and private bypasses, URL
#    query injection via an IPv6 scope suffix), Teredo refused;
#  - check-reputation: quota ledger reserved under a lock, refunded on a
#    failed lookup;
#  - check-signature / hash-file: UNC / device paths refused BEFORE any I/O
#    (SMB egress + NTLM leak).
# Reputation cases need no keys; the refund case makes two keyless-fake
# lookups that are expected to FAIL (bogus key or no network) - that failure
# is exactly what it tests.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$tools = Resolve-Path "$PSScriptRoot\..\src\tier2\tools"

function Invoke-Tool {
    param([string]$Script, [string[]]$ToolArgs)
    $out = & pwsh -NoProfile -File (Join-Path $tools $Script) @ToolArgs
    return ($out -join "`n") | ConvertFrom-Json
}

$root = New-TestStateRoot
try {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $root 'state')
    @{
        detected = @('5.6.7.8'); last_known = @('5.6.7.8')
        recorded_static = @('203.0.113.10'); previous = @()
    } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $root 'state\ownip.json')
    $ledgerFile = Join-Path $root 'state\repquota.json'

    $env:NETWATCH_STATE = $root
    try {
        # --- refusals via alternate spellings --------------------------------
        foreach ($case in @(
                @{ ip = '::ffff:10.0.0.1';      want = 'rfc1918' }
                @{ ip = '167772161';            want = 'rfc1918' }        # decimal 10.0.0.1
                @{ ip = '0x0a000001';           want = 'rfc1918' }
                @{ ip = '::ffff:127.0.0.1';     want = 'loopback' }
                @{ ip = '64:ff9b::a00:1';       want = 'rfc1918' }        # NAT64 10.0.0.1
                @{ ip = '2002:c0a8:101::1';     want = 'rfc1918' }        # 6to4 192.168.1.1
                @{ ip = '::ffff:203.0.113.10';  want = 'own public ip' }  # hardcoded static
                @{ ip = '3405803786';           want = 'own public ip' }
                @{ ip = '64:ff9b::cb00:710a';   want = 'own public ip' }
                @{ ip = '2002:cb00:710a::1';    want = 'own public ip' }
                @{ ip = '::ffff:5.6.7.8';       want = 'own public ip' }  # detected, from state
                @{ ip = '84281096';             want = 'own public ip' }  # decimal 5.6.7.8
                @{ ip = '2001:0:4136:e378::1';  want = 'tunnel' }         # Teredo
                @{ ip = '::ffff:0:cb00:710a';   want = 'own public ip' }  # SIIT own static
                @{ ip = '::ffff:0:a00:1';       want = 'rfc1918' }        # SIIT private
                @{ ip = '64:ff9b:1::cb00:710a'; want = 'tunnel' }         # local-use NAT64
                @{ ip = '::';                   want = 'reserved' }
            )) {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', $case.ip)
            Assert-True ($r.PSObject.Properties['refused']) "refused present for $($case.ip)"
            Assert-Equal $case.want $r.refused "reputation refuses $($case.ip)"
        }

        # --- accepted input is echoed (and looked up) in canonical form ------
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '::ffff:8.8.8.8')
        Assert-Equal '8.8.8.8' $r.ip 'v4-mapped public canonicalized'
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '2001:db8::1%junk&x=y')
        Assert-Equal '2001:db8::1' $r.ip 'scope suffix (URL injection) stripped'
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '134744072')
        Assert-Equal '8.8.8.8' $r.ip 'decimal public canonicalized'
        Assert-False (Test-Path -LiteralPath $ledgerFile) 'keyless runs never touch the ledger'

        # --- ledger: old ISO stamps (auto-DateTime via ConvertFrom-Json) -----
        $recent = [datetime]::UtcNow.AddSeconds(-5).ToString('o')
        @{ date = (Get-Date -Format 'yyyy-MM-dd'); vt_today = 4; abuse_today = 900
           vt_minute = @($recent, $recent, $recent, $recent) } | ConvertTo-Json | Set-Content $ledgerFile
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-True ($r.PSObject.Properties['quota_exhausted']) 'old-format recent stamps still count (4/min)'

        # new compact stamps count too; expired ones are dropped
        $fmt = 'yyyyMMdd\THHmmssfffffff\Z'
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $newRecent = [datetime]::UtcNow.AddSeconds(-5).ToString($fmt, $inv)
        @{ date = (Get-Date -Format 'yyyy-MM-dd'); vt_today = 4; abuse_today = 900
           vt_minute = @($newRecent, $newRecent, $newRecent, $newRecent) } | ConvertTo-Json | Set-Content $ledgerFile
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-True ($r.PSObject.Properties['quota_exhausted']) 'new-format recent stamps count (4/min)'
        $old = [datetime]::UtcNow.AddMinutes(-2).ToString($fmt, $inv)
        @{ date = (Get-Date -Format 'yyyy-MM-dd'); vt_today = 4; abuse_today = 900
           vt_minute = @($old, $old, $old, $old) } | ConvertTo-Json | Set-Content $ledgerFile
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-False ($r.PSObject.Properties['quota_exhausted']) 'expired stamps free the minute window'
        Assert-Equal 'no_key' $r.virustotal_note 'vt allowed again, keyless -> no_key'
        Assert-Equal 'no_key' $r.abuseipdb_note 'keyless abuse reports no_key (key check precedes quota note)'

        # --- ledger lock: a held ledger mutex blocks the tool (fail closed) ---
        Remove-Item -LiteralPath $ledgerFile -Force
        $mutexName = 'netwatch-repquota-' + [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($ledgerFile.ToLowerInvariant()))).Substring(0, 16)
        $m = [System.Threading.Mutex]::new($true, $mutexName)
        $env:NETWATCH_LEDGER_WAIT_MS = '300'
        $env:VT_KEY = 'bogus-test-key'
        try {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
            Assert-Equal 'quota ledger busy' $r.error 'held ledger lock -> busy, no lookup'
            Assert-False (Test-Path -LiteralPath $ledgerFile) 'no ledger write while locked'
        }
        finally {
            $m.ReleaseMutex(); $m.Dispose()
            Remove-Item Env:NETWATCH_LEDGER_WAIT_MS -ErrorAction SilentlyContinue
        }

        # --- reserve + refund: a failed lookup spends nothing -----------------
        $env:ABUSEIPDB_KEY = 'bogus-test-key'
        try {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
            Assert-Equal 'lookup_unavailable' $r.virustotal_note 'bogus vt key -> lookup_unavailable'
            Assert-Equal 'lookup_unavailable' $r.abuseipdb_note 'bogus abuse key -> lookup_unavailable'
            $l = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json
            Assert-Equal 0 $l.vt_today 'vt reservation refunded'
            Assert-Equal 0 $l.abuse_today 'abuse reservation refunded'
            Assert-Equal 0 @($l.vt_minute).Count 'vt minute slot refunded'
            Assert-Equal 400 $r.quota.vt_remaining_today 'reported remaining reflects refund'
        }
        finally {
            Remove-Item Env:VT_KEY, Env:ABUSEIPDB_KEY -ErrorAction SilentlyContinue
        }

        # --- vt_minute stamp is taken INSIDE the lock, after the wait ---------
        # test holds the ledger for ~600 ms (< the 1 s wait), then releases; the
        # stamp in the reservation must not predate the release
        Remove-Item -LiteralPath $ledgerFile -Force -ErrorAction SilentlyContinue
        $hole = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $hole.Start()
        $savedProxy = $env:HTTPS_PROXY
        $env:HTTPS_PROXY = "http://127.0.0.1:$($hole.LocalEndpoint.Port)"
        $env:VT_KEY = 'bogus-test-key'
        $env:NETWATCH_LEDGER_WAIT_MS = '10000'   # tool must outwait the held lock here
        $m = [System.Threading.Mutex]::new($true, $mutexName)
        $owned = $true
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
            foreach ($a in '-NoProfile', '-File', (Join-Path $tools 'check-reputation.ps1'), '-Ip', '8.8.8.8') { $psi.ArgumentList.Add($a) }
            $psi.RedirectStandardOutput = $true
            $psi.UseShellExecute = $false
            $p = [System.Diagnostics.Process]::Start($psi)
            $outTask = $p.StandardOutput.ReadToEndAsync()
            Start-Sleep -Seconds 3          # pwsh startup: tool is now waiting on the mutex
            Start-Sleep -Milliseconds 600
            $released = [datetime]::UtcNow
            $m.ReleaseMutex(); $owned = $false
            $deadline = [datetime]::UtcNow.AddSeconds(10)
            while (-not (Test-Path -LiteralPath $ledgerFile) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 20 }
            $l = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json
            $st = [datetime]::ParseExact([string]@($l.vt_minute)[0], 'yyyyMMdd\THHmmssfffffff\Z',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
            Assert-True ($st -ge $released.AddMilliseconds(-50)) "stamp $($st.ToString('o')) not older than lock release $($released.ToString('o'))"
            $null = $p.WaitForExit(20000)
            $null = $outTask.Result
        }
        finally {
            if ($owned) { $m.ReleaseMutex() }
            $m.Dispose(); $hole.Stop()
            Remove-Item Env:VT_KEY, Env:NETWATCH_LEDGER_WAIT_MS -ErrorAction SilentlyContinue
            if ($savedProxy) { $env:HTTPS_PROXY = $savedProxy } else { Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue }
        }

        # --- busy ledger AFTER the lookup: answer kept, refund skipped --------
        # The VT call goes to a local black-hole proxy (accepts, never
        # answers) so it hangs for its 6 s timeout - a deterministic window in
        # which this test holds the ledger mutex. No traffic leaves the host.
        Remove-Item -LiteralPath $ledgerFile -Force -ErrorAction SilentlyContinue
        $hole = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $hole.Start()
        $savedProxy = $env:HTTPS_PROXY
        $env:HTTPS_PROXY ="http://127.0.0.1:$($hole.LocalEndpoint.Port)"
        $env:VT_KEY = 'bogus-test-key'
        $env:NETWATCH_LEDGER_WAIT_MS = '300'
        $m = [System.Threading.Mutex]::new($false, $mutexName)
        $held = $false
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
            foreach ($a in '-NoProfile', '-File', (Join-Path $tools 'check-reputation.ps1'), '-Ip', '8.8.8.8') { $psi.ArgumentList.Add($a) }
            $psi.RedirectStandardOutput = $true
            $psi.UseShellExecute = $false
            $p = [System.Diagnostics.Process]::Start($psi)
            $outTask = $p.StandardOutput.ReadToEndAsync()
            # reservation written = tool released the mutex and is in its lookup
            $deadline = [datetime]::UtcNow.AddSeconds(15)
            while (-not (Test-Path -LiteralPath $ledgerFile) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 20 }
            Assert-True (Test-Path -LiteralPath $ledgerFile) 'reservation written before the lookup'
            $held = $m.WaitOne(5000)
            Assert-True $held 'test took the ledger mutex during the lookup'
            Assert-True ($p.WaitForExit(20000)) 'tool finished within the MCP 20 s cap'
            $r = $outTask.Result | ConvertFrom-Json
            Assert-False ($r.PSObject.Properties['error']) 'busy ledger after lookup does not turn into an error'
            Assert-Equal 'lookup_unavailable' $r.virustotal_note 'lookup outcome still reported'
            Assert-Equal 'refund_skipped_ledger_busy' $r.quota_note 'skipped refund is flagged'
            $l = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json
            Assert-Equal 1 $l.vt_today 'skipped refund over-counts by one (never over-spends)'
        }
        finally {
            if ($held) { $m.ReleaseMutex() }
            $m.Dispose(); $hole.Stop()
            Remove-Item Env:VT_KEY, Env:NETWATCH_LEDGER_WAIT_MS -ErrorAction SilentlyContinue
            if ($savedProxy) { $env:HTTPS_PROXY = $savedProxy } else { Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue }
        }
    }
    finally { Remove-Item Env:NETWATCH_STATE -ErrorAction SilentlyContinue }
}
finally {
    Remove-TestStateRoot $root
}

# --- path tools: network / device paths refused before any I/O --------------
# Windows path semantics (IsPathRooted, UNC); the hosts are .invalid (RFC 6761)
# so even a regression cannot reach a real machine.
if ($IsWindows) {
    foreach ($tool in 'check-signature.ps1', 'hash-file.ps1') {
        foreach ($p in @(
                '\\attacker.invalid\share\x.exe'
                '//attacker.invalid/share/x.exe'
                '\\?\UNC\attacker.invalid\share\x.exe'
                '\\?\C:\Windows\System32\notepad.exe'
                '\\.\PhysicalDrive0'
            )) {
            $r = Invoke-Tool $tool @('-Path', $p)
            Assert-Equal 'network or device path denied by policy' $r.error "$tool refuses $p"
        }
        # a normal local file still works
        $r = Invoke-Tool $tool @('-Path', (Join-Path $tools $tool))
        Assert-False ($r.PSObject.Properties['error']) "$tool accepts a local drive path"
    }

    # --- reparse points: links are vetted hop by hop before any open --------
    $lroot = New-TestStateRoot
    try {
        # junction (no admin needed) into a Downloads-shaped directory
        $dl = Join-Path $lroot ('Users\someone\' + 'Down' + 'loads')
        $null = New-Item -ItemType Directory -Force -Path $dl
        'x' | Set-Content (Join-Path $dl 'evil.exe')
        $j = Join-Path $lroot 'innocent'
        $null = New-Item -ItemType Junction -Path $j -Target $dl
        # local non-Downloads junction still works
        $ok = Join-Path $lroot 'okdir'
        $null = New-Item -ItemType Directory -Force -Path $ok
        'y' | Set-Content (Join-Path $ok 'fine.exe')
        $j2 = Join-Path $lroot 'okjunction'
        $null = New-Item -ItemType Junction -Path $j2 -Target $ok
        # symlink to a UNC share: needs SeCreateSymbolicLinkPrivilege (admin
        # or Developer Mode); .NET does not touch the target when creating it
        $uncLink = Join-Path $lroot 'share'
        $haveUnc = $true
        try { $null = [IO.Directory]::CreateSymbolicLink($uncLink, '\\attacker.invalid\share') }
        catch { $haveUnc = $false; Write-Host "SKIP: symlink-to-UNC case (no symlink privilege: $($_.Exception.Message))" -ForegroundColor Yellow }

        foreach ($tool in 'check-signature.ps1', 'hash-file.ps1') {
            $r = Invoke-Tool $tool @('-Path', (Join-Path $j 'evil.exe'))
            Assert-Equal 'path denied by policy' $r.error "${tool}: junction into Downloads denied"
            $r = Invoke-Tool $tool @('-Path', (Join-Path $j2 'fine.exe'))
            Assert-False ($r.PSObject.Properties['error']) "${tool}: local junction allowed"
            if ($haveUnc) {
                $r = Invoke-Tool $tool @('-Path', (Join-Path $uncLink 'x.exe'))
                Assert-Equal 'network or device path denied by policy' $r.error "${tool}: symlink to UNC denied"
            }
        }
    }
    finally {
        foreach ($lnk in 'innocent', 'okjunction', 'share') {
            $lp = Join-Path $lroot $lnk
            # no Test-Path: it would follow the UNC link. Delete removes the
            # link itself, never its target.
            try { [IO.Directory]::Delete($lp) } catch {}
        }
        Remove-TestStateRoot $lroot
    }
}

Complete-Tests
