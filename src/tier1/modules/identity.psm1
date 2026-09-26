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
#                back to name-only - failing closed here would turn every
#                system service into residual noise. A user-level impostor
#                ALWAYS has a readable path, so it cannot hide in this case.
#   'mismatch' - pinned, path readable, path or signer wrong: the connection
#                matches NO whitelist entry and NO browser policy (residual)
#
# Pins = built-in defaults (OS binaries with a single fixed location, Edge)
# overlaid by the whitelist's optional top-level "process_images" (a name
# given there REPLACES the built-in pin for that name). Paths may use
# %ENV% variables and -like wildcards; comparison is case-insensitive.

Set-StrictMode -Version Latest

$script:BuiltinPins = @{
    'svchost'            = @{ paths = @('%SystemRoot%\System32\svchost.exe') }
    'explorer'           = @{ paths = @('%SystemRoot%\explorer.exe') }
    'taskhostw'          = @{ paths = @('%SystemRoot%\System32\taskhostw.exe') }
    'runtimebroker'      = @{ paths = @('%SystemRoot%\System32\RuntimeBroker.exe') }
    'backgroundtaskhost' = @{ paths = @('%SystemRoot%\System32\backgroundTaskHost.exe') }
    'msedge'             = @{ paths = @('%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe'
                                        '%ProgramFiles%\Microsoft\Edge\Application\msedge.exe') }
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

function Test-ProcessIdentity {
    param(
        [Parameter(Mandatory)] $Conn,
        $Whitelist
    )
    $pins = Get-ProcessPins -Whitelist $Whitelist
    $name = ([string]$Conn.name).ToLowerInvariant()
    if (-not $pins.ContainsKey($name)) { return 'unpinned' }
    $pin = $pins[$name]
    $img = [string]$Conn.image_path
    if (-not $img) { return 'unknown' }

    $pathOk = $false
    foreach ($pattern in @($pin.paths)) {
        $expanded = [Environment]::ExpandEnvironmentVariables([string]$pattern)
        if ($img -like $expanded) { $pathOk = $true; break }
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

Export-ModuleMember -Function Test-ProcessIdentity, Get-ProcessPins, Set-SignerProvider
