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
                @{ ip = 'fec0::1';              want = 'site-local' }      # deprecated site-local
                @{ ip = '2001:db8::1';          want = 'documentation' }   # RFC 3849
            )) {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', $case.ip)
            Assert-True ($r.PSObject.Properties['refused']) "refused present for $($case.ip)"
            Assert-Equal $case.want $r.refused "reputation refuses $($case.ip)"
        }

        # --- accepted input is echoed (and looked up) in canonical form ------
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '::ffff:8.8.8.8')
        Assert-Equal '8.8.8.8' $r.ip 'v4-mapped public canonicalized'
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '2606:4700::1%junk&x=y')
        Assert-Equal '2606:4700::1' $r.ip 'scope suffix (URL injection) stripped'
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

# --- fail-closed state handling (review 2026-09-26) --------------------------
$root = New-TestStateRoot
try {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $root 'state')
    $env:NETWATCH_STATE = $root
    try {
        # a readable ownip.json that yields no own IP proves nothing
        '{}' | Set-Content (Join-Path $root 'state\ownip.json')
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-Equal 'own-ip state empty (fail closed)' $r.refused 'empty own-ip state refuses'
        @{ detected = @('5.6.7.8'); last_known = @(); recorded_static = @(); previous = @() } |
            ConvertTo-Json | Set-Content (Join-Path $root 'state\ownip.json')

        # a torn ledger must not re-zero the day's counters
        $ledgerFile = Join-Path $root 'state\repquota.json'
        '{"date":"20' | Set-Content $ledgerFile
        $env:VT_KEY = 'bogus-test-key'
        try {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
            Assert-Equal 'quota ledger unreadable' $r.error 'torn ledger -> no lookup (fail closed)'
            Assert-Equal '{"date":"20' (Get-Content $ledgerFile -Raw).Trim() 'torn ledger left untouched for housekeeping'
            '{"date":"2026-01-01"}' | Set-Content $ledgerFile            # parses, but fields missing
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
            Assert-Equal 'quota ledger unreadable' $r.error 'malformed ledger (missing fields) -> fail closed'
            'null' | Set-Content $ledgerFile                             # valid JSON, not an object
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
            Assert-Equal 'quota ledger unreadable' $r.error 'JSON-null ledger -> fail closed'
        }
        finally { Remove-Item Env:VT_KEY -ErrorAction SilentlyContinue }
        Assert-Equal 0 @(Get-ChildItem (Join-Path $root 'state') -Filter '*.tmp').Count 'no temp files left behind'
    }
    finally { Remove-Item Env:NETWATCH_STATE -ErrorAction SilentlyContinue }
}
finally { Remove-TestStateRoot $root }

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
        catch { $haveUnc = $false; Skip-Test "symlink-to-UNC cases (no symlink privilege: $($_.Exception.Message))" }

        # --- bypasses found by the 2026-09-26 reviews ---------------------------
        # (a) junction onto a PROFILE: C:\a -> ...\Users\victim, path a\Downloads\x
        $victim = Join-Path $lroot 'Users\victim'
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $victim ('Down' + 'loads'))
        'z' | Set-Content (Join-Path $victim (('Down' + 'loads') + '\evil.exe'))
        $null = New-Item -ItemType Junction -Path (Join-Path $lroot 'profj') -Target $victim
        # (b) link INSIDE a link target: chain -> mid, mid\inner -> Downloads
        $mid = Join-Path $lroot 'mid'
        $null = New-Item -ItemType Directory -Force -Path $mid
        $null = New-Item -ItemType Junction -Path (Join-Path $mid 'inner') -Target $dl
        $null = New-Item -ItemType Junction -Path (Join-Path $lroot 'chain') -Target $mid
        # (c) '..' inside a stored junction target (mklink keeps the string as given)
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $lroot 'Users\someone\Documents')
        $dotTarget = Join-Path $lroot ('Users\someone\Documents\..\' + 'Down' + 'loads')
        $null = cmd /c mklink /J "$(Join-Path $lroot 'dotj')" "$dotTarget"
        # (c2) a RELATIVE symlink target keeps '..' verbatim (mklink /J may
        # store an already-normalized absolute path)
        if ($haveUnc) {
            $null = [IO.Directory]::CreateSymbolicLink((Join-Path $lroot 'dotl'), ('Users\someone\Documents\..\' + 'Down' + 'loads'))
        }
        # (d) link whose target sits under another link that points at UNC:
        # ja -> share\sub, share -> \\attacker.invalid\share (needs symlink privilege)
        if ($haveUnc) {
            $null = [IO.Directory]::CreateSymbolicLink((Join-Path $lroot 'ja'), (Join-Path $uncLink 'sub'))
        }
        # (e) 8.3 short name of the Downloads-shaped dir (only if 8.3 is enabled here)
        $short = $null
        try { $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($dl).ShortPath } catch {}
        # (f) subst drive onto the Downloads-shaped dir
        $substLetter = @('Q', 'R', 'S', 'T', 'U', 'V', 'W') | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -First 1
        $haveSubst = $false
        if ($substLetter) { $null = subst "${substLetter}:" "$dl"; $haveSubst = ($LASTEXITCODE -eq 0) }

        foreach ($tool in 'check-signature.ps1', 'hash-file.ps1') {
            $r = Invoke-Tool $tool @('-Path', (Join-Path $j 'evil.exe'))
            Assert-Equal 'path denied by policy' $r.error "${tool}: junction into Downloads denied"
            $r = Invoke-Tool $tool @('-Path', (Join-Path $j2 'fine.exe'))
            Assert-False ($r.PSObject.Properties['error']) "${tool}: local junction allowed"
            Assert-True ((Join-Path $ok 'fine.exe') -ieq $r.path) "${tool}: reports the OS final path, not the link path ($($r.path))"
            if ($haveUnc) {
                $r = Invoke-Tool $tool @('-Path', (Join-Path $uncLink 'x.exe'))
                Assert-Equal 'network or device path denied by policy' $r.error "${tool}: symlink to UNC denied"
                $r = Invoke-Tool $tool @('-Path', (Join-Path $lroot 'ja\x.exe'))
                Assert-Equal 'network or device path denied by policy' $r.error "${tool}: UNC link inside a link target denied"
            }
            $r = Invoke-Tool $tool @('-Path', (Join-Path $lroot (('profj\' + 'Down' + 'loads') + '\evil.exe')))
            Assert-Equal 'path denied by policy' $r.error "${tool}: junction onto a profile -> Downloads denied"
            $r = Invoke-Tool $tool @('-Path', (Join-Path $lroot 'chain\inner\evil.exe'))
            Assert-Equal 'path denied by policy' $r.error "${tool}: link inside a link target -> Downloads denied"
            $r = Invoke-Tool $tool @('-Path', (Join-Path $lroot 'dotj\evil.exe'))
            Assert-Equal 'path denied by policy' $r.error "${tool}: '..' in a junction target -> Downloads denied"
            if ($haveUnc) {
                $r = Invoke-Tool $tool @('-Path', (Join-Path $lroot 'dotl\evil.exe'))
                Assert-Equal 'path denied by policy' $r.error "${tool}: relative '..' symlink target -> Downloads denied"
            }
            # GetFullPath already strips a trailing dot from middle segments
            # (CI, 2026-09-26); the segment rule is the backstop for any form
            # it keeps. Either way the checked entry must be the opened one.
            $trailErr = 'trailing dot or space in a path segment denied by policy'
            $r = Invoke-Tool $tool @('-Path', "$dl.\evil.exe")
            Assert-True ($r.error -in 'path denied by policy', $trailErr) "${tool}: trailing dot on Downloads denied ($($r.error))"
            # security invariant: denied, or exactly the real file - never a
            # different entry than the one checked
            $r = Invoke-Tool $tool @('-Path', "$ok \fine.exe")
            $rErr = $r.PSObject.Properties['error']?.Value
            $rPath = $r.PSObject.Properties['path']?.Value
            Write-Host "INFO: ${tool} trailing-space middle segment -> error=[$rErr] path=[$rPath]"
            Assert-True ([bool]$rErr -or ((Join-Path $ok 'fine.exe') -ieq $rPath)) "${tool}: trailing space in a middle segment: denied or the same real file"
            $r = Invoke-Tool $tool @('-Path', "$(Join-Path $ok 'fine.exe'):hidden")
            Assert-Equal 'alternate data stream denied by policy' $r.error "${tool}: NTFS stream denied"
            $r = Invoke-Tool $tool @('-Path', "${dl}:hidden")
            Assert-True ($r.error -in 'alternate data stream denied by policy', 'path denied by policy') "${tool}: stream on Downloads denied"
            $r = Invoke-Tool $tool @('-Path', (Join-Path $ok 'no-such.exe'))
            Assert-Equal 'file not found' $r.error "${tool}: missing file still reported as not found"
            if ($short -and $short -ne $dl) {
                $r = Invoke-Tool $tool @('-Path', (Join-Path $short 'evil.exe'))
                Assert-Equal 'path denied by policy' $r.error "${tool}: 8.3 short name of Downloads denied ($short)"
            }
            else { Skip-Test "${tool}: 8.3 case - short names disabled on this volume" }
            if ($haveSubst) {
                $r = Invoke-Tool $tool @('-Path', "${substLetter}:\evil.exe")
                Assert-Equal 'path denied by policy' $r.error "${tool}: subst drive onto Downloads denied"
            }
            else { Skip-Test "${tool}: subst case - no free drive letter or subst failed" }
        }
    }
    finally {
        if ($haveSubst) { $null = subst "${substLetter}:" /d }
        foreach ($lnk in 'mid\inner') { try { [IO.Directory]::Delete((Join-Path $lroot $lnk)) } catch {} }
        foreach ($lnk in 'innocent', 'okjunction', 'share', 'profj', 'chain', 'dotj', 'dotl', 'ja') {
            $lp = Join-Path $lroot $lnk
            # no Test-Path: it would follow the UNC link. Delete removes the
            # link itself, never its target.
            try { [IO.Directory]::Delete($lp) } catch {}
        }
        Remove-TestStateRoot $lroot
    }
}

Complete-Tests
