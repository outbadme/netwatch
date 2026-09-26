# identity.tests.ps1 - process identity pinning (identity.psm1) and its effect
# on classification: a pinned name from the wrong image path / signer gets no
# whitelist and no browser credit. Platform-neutral: env vars the built-in
# pins use are set here, signatures come from the provider seam.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\classify.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\identity.psm1"   # same instance classify uses

if (-not $env:SystemRoot)         { $env:SystemRoot = 'C:\Windows' }
if (-not $env:ProgramFiles)       { $env:ProgramFiles = 'C:\Program Files' }
if (-not ${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} = 'C:\Program Files (x86)' }
$sys32 = "$($env:SystemRoot)\System32"          # string concat: Join-Path needs the drive to exist

function New-Conn {
    param([hashtable]$O = @{})
    $c = @{
        pid = 1234; name = 'proc'; image_path = $null; image_exists = $true
        command_line = ''; laddr = '192.168.1.10'; lport = 50000
        raddr = '193.57.46.213'; rport = 443; state = 'Established'
        direction = 'outbound'; domain = $null; attribution_source = 'none'
    }
    foreach ($k in $O.Keys) { $c[$k] = $O[$k] }
    return $c
}

$root = New-TestStateRoot
try {
    $cfg = Get-NetwatchConfig -Path (New-TestConfig -StateRoot $root)
    Initialize-StateRoot -Config $cfg
    $wl = Get-Whitelist -Config $cfg          # repo seed; no process_images -> built-ins only

    # --- built-in pin: svchost ------------------------------------------------
    $real = "$sys32\svchost.exe"
    $fake = 'C:\Users\victim\AppData\Local\Temp\svchost.exe'
    $c = New-Conn @{ name = 'svchost'; image_path = $real; rport = 7680 }
    Assert-Equal 'verified' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'real svchost verified'
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'real svchost:7680 whitelisted'
    $c = New-Conn @{ name = 'svchost'; image_path = $real.ToUpperInvariant(); rport = 7680 }
    Assert-Equal 'verified' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'path comparison case-insensitive'

    $c = New-Conn @{ name = 'svchost'; image_path = $fake; rport = 7680 }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'svchost from Temp is a mismatch'
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'impostor svchost:7680 NOT whitelisted'
    Assert-Equal 'mismatch' $c.identity 'identity recorded on the conn for the packet'
    $c = New-Conn @{ name = 'svchost'; image_path = $fake; domain = 'update.microsoft.com'; attribution_source = 'sni' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'impostor svchost to a microsoft domain NOT whitelisted'

    # unreadable path (non-elevated WMI on a SYSTEM service): name-only
    # fallback for entries with a destination, none for any-peer entries
    $c = New-Conn @{ name = 'svchost'; image_path = $null; rport = 7680 }
    Assert-Equal 'unknown' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'null path -> unknown'
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unknown: no constraint-only (any-peer) entry'
    $c = New-Conn @{ name = 'svchost'; image_path = $null; raddr = '4.208.1.1'; rport = 443 }
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unknown: destination entry still matches by name'
    $c = New-Conn @{ name = 'svchost'; image_path = "$($env:SystemRoot)\SysWOW64\svchost.exe"; rport = 7680 }
    Assert-Equal 'verified' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'SysWOW64 svchost verified'

    # dosvc is a service inside svchost: a dosvc.exe is never legitimate
    $c = New-Conn @{ name = 'dosvc'; image_path = 'C:\Windows\System32\dosvc.exe'; rport = 80 }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'any dosvc image -> mismatch'
    $c = New-Conn @{ name = 'dosvc'; image_path = $null; rport = 80 }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'dosvc with unreadable image -> mismatch'

    # --- built-in pin: msedge and the browser policy ---------------------------
    Set-SignerProvider { param($p) 'Microsoft Corporation' }
    $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $c = New-Conn @{ name = 'msedge'; image_path = $edge; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'browser-attributed' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'real Edge keeps browser policy'
    $c = New-Conn @{ name = 'msedge'; image_path = 'C:\Users\victim\Downloads\msedge.exe'; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'fake msedge loses browser policy'
    # per-user roots: a Windows-shaped LOCALAPPDATA only for these checks (the
    # test state root is built from the real one)
    $savedLad = $env:LOCALAPPDATA
    $lad = if ($IsWindows) { $env:LOCALAPPDATA } else { 'C:\Users\me\AppData\Local' }
    $env:LOCALAPPDATA = $lad
    foreach ($ch in "${env:ProgramFiles(x86)}\Microsoft\Edge Beta\Application\msedge.exe",
                    "$($env:LOCALAPPDATA)\Microsoft\Edge SxS\Application\msedge.exe") {
        $c = New-Conn @{ name = 'msedge'; image_path = $ch }
        Assert-Equal 'verified' (Test-ProcessIdentity -Conn $c -Whitelist $wl) "Edge channel verified: $ch"
    }
    foreach ($wv in "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\140.0.1.2\msedgewebview2.exe",
                    "$($env:LOCALAPPDATA)\Microsoft\EdgeWebView\Application\140.0.1.2\msedgewebview2.exe") {
        $c = New-Conn @{ name = 'msedgewebview2'; image_path = $wv }
        Assert-Equal 'verified' (Test-ProcessIdentity -Conn $c -Whitelist $wl) "signed WebView2 verified: $wv"
    }
    # a genuine signed binary copied elsewhere (DLL side-load) is not verified
    foreach ($x in @(@('msedge', 'C:\Users\victim\Downloads\Microsoft\Edge\Application\msedge.exe'),
                     @('msedgewebview2', 'C:\Program Files\SomeApp\webview\msedgewebview2.exe'))) {
        $c = New-Conn @{ name = $x[0]; image_path = $x[1] }
        Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl) "signed copy outside the install roots: $($x[1])"
    }
    $env:LOCALAPPDATA = $savedLad
    Set-SignerProvider { param($p) 'Evil Ltd' }
    $c = New-Conn @{ name = 'msedgewebview2'; image_path = 'C:\Users\victim\Downloads\msedgewebview2.exe' }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'WebView2 with a foreign signer -> mismatch'
    $c = New-Conn @{ name = 'msedge'; image_path = $edge; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'Edge path with a foreign signer loses browser policy'
    Set-SignerProvider $null

    # env values are literal inside a pin pattern (a profile named 'a[1]')
    $env:NW_TEST_PROFILE = 'C:\Users\a[1]'
    Assert-True ('C:\Users\a[1]\x.exe' -like (Expand-PinPattern -Pattern '%NW_TEST_PROFILE%\x.exe')) 'bracket in env value matches literally'
    Assert-False ('C:\Users\a1\x.exe' -like (Expand-PinPattern -Pattern '%NW_TEST_PROFILE%\x.exe')) 'bracket in env value is not a wildcard set'
    Remove-Item Env:NW_TEST_PROFILE

    # the dosvc pin cannot be overridden into 'verified'
    $wlD = $wl | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $wlD | Add-Member -NotePropertyName process_images -NotePropertyValue ([pscustomobject]@{ dosvc = @('C:\x\dosvc.exe') })
    $c = New-Conn @{ name = 'dosvc'; image_path = 'C:\x\dosvc.exe' }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wlD) 'process_images cannot re-enable dosvc'

    # unpinned browser names are reported (operator WARN at load)
    $un = @(Get-UnpinnedNames -Names @('msedge', 'msedgewebview2', 'octium') -Whitelist $wl)
    Assert-Equal 'octium' ($un -join ',') 'only the unpinned browser name is reported'

    # --- unpinned names behave exactly as before ------------------------------
    $c = New-Conn @{ name = 'claude'; image_path = 'D:\anywhere\claude.exe'; domain = 'api.anthropic.com'; attribution_source = 'sni' }
    Assert-Equal 'unpinned' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'unpinned name'
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unpinned whitelisting unchanged'

    # --- whitelist process_images: paths + signers, override of a built-in -----
    $wl2 = $wl | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $wl2 | Add-Member -NotePropertyName process_images -NotePropertyValue ([pscustomobject]@{
            telegram = [pscustomobject]@{ paths = @('C:\Apps\Telegram\Telegram.exe'); signers = @('Telegram FZ-LLC') }
            svchost  = @('C:\Custom\svchost.exe')                      # replaces the built-in
        })
    $calls = [ref]0
    Set-SignerProvider { param($p) $calls.Value++; if ($p -like '*Telegram.exe') { 'Telegram FZ-LLC' } else { '' } }
    $tg = New-Conn @{ name = 'telegram'; image_path = 'C:\Apps\Telegram\Telegram.exe'; raddr = '149.154.161.5' }
    Assert-Equal 'verified' (Test-ProcessIdentity -Conn $tg -Whitelist $wl2) 'path + signer verified'
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl2 -Conn $tg -Config $cfg) 'verified telegram whitelisted'
    $null = Test-ProcessIdentity -Conn $tg -Whitelist $wl2
    Assert-Equal 1 $calls.Value 'signer lookup cached per image'
    $c = New-Conn @{ name = 'svchost'; image_path = $real; rport = 7680 }
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $c -Whitelist $wl2) 'whitelist pin replaces the built-in'

    Set-SignerProvider { param($p) '' }                                  # not Valid
    $tg2 = New-Conn @{ name = 'telegram'; image_path = 'C:\Apps\Telegram\Telegram.exe' }
    $wl3 = $wl2 | ConvertTo-Json -Depth 10 | ConvertFrom-Json           # new object -> fresh pin cache
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $tg2 -Whitelist $wl3) 'unsigned image with pinned signer -> mismatch'
    Set-SignerProvider { param($p) throw 'no Authenticode here' }
    $wl4 = $wl2 | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    Assert-Equal 'mismatch' (Test-ProcessIdentity -Conn $tg2 -Whitelist $wl4) 'signature check failure fails closed'
    Set-SignerProvider $null

    # --- identity reaches the Tier-2 packet (schema-validated by the builder) --
    Import-Module "$PSScriptRoot\..\src\tier1\modules\escalate.psm1" -Force
    $imp = New-Conn @{ name = 'svchost'; image_path = $fake; rport = 7680 }
    $null = Get-Classification -Whitelist $wl -Conn $imp -Config $cfg
    $queue = @{}
    $now = [datetime]::UtcNow
    $k = Update-ResidualQueue -Queue $queue -Conn $imp -NowUtc $now
    $pkt = Build-EscalationPacket -Keys @($k) -Queue $queue -Config $cfg `
        -Health @{ sni_capture = 'ok'; dns_etw = 'ok' } -NowUtc $now
    Assert-Equal 'mismatch' $pkt.connections[0].process.identity 'packet carries identity=mismatch (and passed its schema)'

    # --- schemas ---------------------------------------------------------------
    $wlSchema = "$PSScriptRoot\..\schemas\whitelist.schema.json"
    $ok = @{ version = 1; entries = @(); process_images = @{
            a = @('C:\x\a.exe'); b = @{ paths = @('C:\x\b.exe'); signers = @('B Corp') } } } | ConvertTo-Json -Depth 6
    Assert-True (Test-Json -Json $ok -SchemaFile $wlSchema -ErrorAction SilentlyContinue) 'process_images array/object forms valid'
    $bad = @{ version = 1; entries = @(); process_images = @{ a = @() } } | ConvertTo-Json -Depth 6
    Assert-False (Test-Json -Json $bad -SchemaFile $wlSchema -ErrorAction SilentlyContinue) 'empty path list rejected'
    $bad = @{ version = 1; entries = @(); process_images = @{ a = @{ signers = @('x') } } } | ConvertTo-Json -Depth 6
    Assert-False (Test-Json -Json $bad -SchemaFile $wlSchema -ErrorAction SilentlyContinue) 'signers without paths rejected'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
