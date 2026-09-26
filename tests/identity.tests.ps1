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

    # unreadable path (non-elevated WMI on a SYSTEM service): name-only fallback
    $c = New-Conn @{ name = 'svchost'; image_path = $null; rport = 7680 }
    Assert-Equal 'unknown' (Test-ProcessIdentity -Conn $c -Whitelist $wl) 'null path -> unknown'
    Assert-Equal 'whitelisted' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'unknown falls back to name-only'

    # --- built-in pin: msedge and the browser policy ---------------------------
    $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $c = New-Conn @{ name = 'msedge'; image_path = $edge; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'browser-attributed' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'real Edge keeps browser policy'
    $c = New-Conn @{ name = 'msedge'; image_path = 'C:\Users\victim\Downloads\msedge.exe'; domain = 'random-site.example'; attribution_source = 'sni' }
    Assert-Equal 'residual' (Get-Classification -Whitelist $wl -Conn $c -Config $cfg) 'fake msedge loses browser policy'

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
