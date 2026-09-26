# identity.psm1 - process identity pinning. Whitelist entries and the browser
# policy match on the process NAME, which any binary can choose (a dropper
# named svchost.exe in %TEMP%, a stub named msedge.exe). A pinned name counts
# as that process only when its image path matches (and, when signers are
# pinned, the image carries a Valid Authenticode signature from one of them).
#
# Result of Test-ProcessIdentity:
#   'unpinned' - no pin for this name: name-only matching as before
#   'verified' - pinned and the image path (+ signer) matches
#   'unknown'  - pinned, but the image path is unreadable (non-elevated WMI
#                returns no ExecutablePath for SYSTEM/PPL processes): falls
#                back to name-only for entries WITH a destination - failing
#                closed there would turn every system service into residual
#                noise. It gets no browser credit and no constraint-only
#                (any-peer) entry: those would trust the bare name for
#                arbitrary destinations (classify.psm1).
#   'mismatch' - pinned, path readable, path or signer wrong: the connection
#                matches NO whitelist entry and NO browser policy (residual)
#
# Pins = built-in defaults (OS binaries with fixed locations; Edge and
# WebView2 by install layout + Microsoft signature, since channels and
# fixed-version WebView2 runtimes live in many places) overlaid by the
# whitelist's optional top-level "process_images" (a name given there
# REPLACES the built-in pin for that name, except an empty one). Paths may use %ENV% variables and
# -like wildcards; comparison is case-insensitive. Characters in an EXPANDED
# variable are literal (a profile named 'a[1]' is not a wildcard set).
# An empty paths list = no legitimate image exists (the name alone is a lie).

Set-StrictMode -Version Latest

$script:BuiltinPins = @{
    'svchost'            = @{ paths = @('%SystemRoot%\System32\svchost.exe'
                                        '%SystemRoot%\SysWOW64\svchost.exe'
                                        '%SystemRoot%\SysArm32\svchost.exe') }
    # DoSvc is a service INSIDE svchost; no dosvc.exe ships with Windows
    'dosvc'              = @{ paths = @() }
    'explorer'           = @{ paths = @('%SystemRoot%\explorer.exe') }
    'taskhostw'          = @{ paths = @('%SystemRoot%\System32\taskhostw.exe') }
    'runtimebroker'      = @{ paths = @('%SystemRoot%\System32\RuntimeBroker.exe') }
    'backgroundtaskhost' = @{ paths = @('%SystemRoot%\System32\backgroundTaskHost.exe') }
    # stable/Beta/Dev under Program Files, Canary ('Edge SxS') per user. The
    # roots matter: a signed msedge.exe copied next to a planted DLL anywhere
    # else is a classic side-load and must not get browser credit
    'msedge'             = @{ paths   = @('%ProgramFiles(x86)%\Microsoft\Edge*\Application\msedge.exe'
                                          '%ProgramFiles%\Microsoft\Edge*\Application\msedge.exe'
                                          '%LOCALAPPDATA%\Microsoft\Edge SxS\Application\msedge.exe')
                              signers = @('Microsoft Corporation') }
    # Evergreen runtime (EdgeWebView\Application\<ver>\, machine or per
    # user). A fixed-version runtime shipped inside an app needs its own
    # process_images entry.
    'msedgewebview2'     = @{ paths   = @('%ProgramFiles(x86)%\Microsoft\Edge*\Application\*\msedgewebview2.exe'
                                          '%ProgramFiles%\Microsoft\Edge*\Application\*\msedgewebview2.exe'
                                          '%LOCALAPPDATA%\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe')
                              signers = @('Microsoft Corporation') }
}

$script:PinCache = @{ source = $null; pins = $null }
$script:SignerCache = @{}          # "path|mtime|size" -> signer CN or '' (not Valid)
$script:DefaultSignerProvider = {
    # image path -> signer CN when the Authenticode signature is Valid, else ''
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ("$($sig.Status)" -ne 'Valid' -or -not $sig.SignerCertificate) { return '' }
    return $sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
}
$script:SignerProvider = $script:DefaultSignerProvider

function Set-SignerProvider {
    # Test seam: replace the Authenticode lookup; $null restores the default.
    param([scriptblock]$Provider)
    $script:SignerProvider = if ($Provider) { $Provider } else { $script:DefaultSignerProvider }
    $script:SignerCache = @{}
}

function Get-ProcessPins {
    # Merged pin table (lowercase name -> @{ paths; signers }), cached per
    # whitelist object (hot path: called for every connection).
    param($Whitelist)
    if ($null -ne $Whitelist -and [object]::ReferenceEquals($script:PinCache.source, $Whitelist)) {
        return $script:PinCache.pins
    }
    $pins = @{}
    foreach ($k in $script:BuiltinPins.Keys) { $pins[$k] = $script:BuiltinPins[$k] }
    if ($null -ne $Whitelist -and $Whitelist.PSObject.Properties['process_images']) {
        foreach ($p in $Whitelist.process_images.PSObject.Properties) {
            # a built-in "no legitimate image" pin (dosvc) is not overridable
            $bi = $script:BuiltinPins[$p.Name.ToLowerInvariant()]
            if ($bi -and @($bi.paths).Count -eq 0) { continue }
            $v = $p.Value
            $pin = if ($v -is [string] -or $v -is [array]) { @{ paths = @($v) } }
                   else {
                       @{ paths   = @(if ($v.PSObject.Properties['paths'])   { $v.paths })
                          signers = @(if ($v.PSObject.Properties['signers']) { $v.signers }) }
                   }
            $pins[$p.Name.ToLowerInvariant()] = $pin
        }
    }
    $script:PinCache = @{ source = $Whitelist; pins = $pins }
    return $pins
}

function Get-ImageSigner {
    param([Parameter(Mandatory)] [string]$Path)
    $key = $Path
    try {
        $fi = [IO.FileInfo]::new($Path)
        if ($fi.Exists) { $key = '{0}|{1}|{2}' -f $Path, $fi.LastWriteTimeUtc.Ticks, $fi.Length }
    }
    catch {}
    if ($script:SignerCache.ContainsKey($key)) { return $script:SignerCache[$key] }
    $cn = $null
    try { $cn = [string](& $script:SignerProvider $Path) } catch { $cn = $null }   # $null = could not check
    if ($null -ne $cn) { $script:SignerCache[$key] = $cn }
    return $cn
}

function Expand-PinPattern {
    # %VAR% -> its value with wildcard characters escaped; the pattern's own
    # * ? [ ] stay wildcards. Undefined variables stay literal (no match).
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Pattern)
    return [regex]::Replace($Pattern, '%([^%]+)%', {
            param($m)
            $v = [Environment]::GetEnvironmentVariable($m.Groups[1].Value)
            if ($null -eq $v) { return $m.Value }
            return [Management.Automation.WildcardPattern]::Escape($v)
        })
}

function Test-ProcessIdentity {
    param(
        [Parameter(Mandatory)] $Conn,
        $Whitelist
    )
    $pins = Get-ProcessPins -Whitelist $Whitelist
    $name = ([string]$Conn.name).ToLowerInvariant()
    if (-not $pins.ContainsKey($name)) { return 'unpinned' }
    $pin = $pins[$name]
    if (@($pin.paths).Count -eq 0) { return 'mismatch' }       # no legitimate image exists
    $img = [string]$Conn.image_path
    if (-not $img) { return 'unknown' }

    $pathOk = $false
    foreach ($pattern in @($pin.paths)) {
        if ($img -like (Expand-PinPattern -Pattern ([string]$pattern))) { $pathOk = $true; break }
    }
    if (-not $pathOk) { return 'mismatch' }

    $signers = @()
    if ($pin.ContainsKey('signers')) { $signers = @(@($pin.signers) | Where-Object { $_ }) }
    if ($signers.Count) {
        $cn = Get-ImageSigner -Path $img
        # could not check (provider failed) or not Valid: fail closed - the
        # connection stays residual and Tier 2 looks at it
        if (-not $cn -or $cn -notin $signers) { return 'mismatch' }
    }
    return 'verified'
}

function Get-UnpinnedNames {
    # Names from $Names with no identity pin: the operator is told once at
    # load (a browser entry grants credit for ANY domain to that bare name).
    param([string[]]$Names, $Whitelist)
    $pins = Get-ProcessPins -Whitelist $Whitelist
    return @(@($Names) | Where-Object { $_ -and -not $pins.ContainsKey($_.ToLowerInvariant()) })
}

Export-ModuleMember -Function Get-UnpinnedNames, Test-ProcessIdentity, Get-ProcessPins, Set-SignerProvider, Expand-PinPattern
