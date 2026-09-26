# check-signature.ps1 - Tier-2 MCP tool backend. READ-ONLY.
# pwsh 7 MANDATORY: on this machine PS 5.1 silently fails to load
# Microsoft.PowerShell.Security -> Get-AuthenticodeSignature false "all clear".
# Output: single JSON object on stdout.

#Requires -Version 7.4
param([Parameter(Mandatory)] [string]$Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

# --- input validation (non-negotiable, model-independent) --------------------
if (-not [IO.Path]::IsPathRooted($Path))                 { Out-Result @{ error = 'path must be absolute' } }
# Local drive-letter paths only, checked on the RAW string before anything
# touches the filesystem: UNC (\\host\share, \\?\UNC\, //host/share) and
# device paths would make Test-Path/Get-AuthenticodeSignature open an SMB
# session - network egress plus the user's NTLM hash handed to whatever host
# hostile packet text talked the model into (review finding).
if ($Path -notmatch '^[A-Za-z]:[\\/]')                  { Out-Result @{ error = 'network or device path denied by policy' } }
# Normalize BEFORE the deny check: GetFullPath collapses forward slashes,
# ./.. segments AND expands 8.3 short names (verified on this volume) - the
# raw-string regex alone was bypassable (review finding).
try { $Path = [IO.Path]::GetFullPath($Path) } catch { Out-Result @{ error = 'path not normalizable' } }
if ($Path -notmatch '^[A-Za-z]:\\')                     { Out-Result @{ error = 'network or device path denied by policy' } }
if ($Path -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { Out-Result @{ error = 'path denied by policy' } }
# a mapped network drive (Z: -> \\host\share) is SMB behind a drive letter
try { $driveType = [IO.DriveInfo]::new($Path.Substring(0, 1)).DriveType } catch { $driveType = 'Unknown' }
if ("$driveType" -in 'Network', 'NoRootDirectory', 'Unknown') { Out-Result @{ error = 'network or device path denied by policy' } }
# Reparse points (symlink/junction) on a local drive can lead to a UNC share
# or into Downloads - the string checks above never see the target (review
# finding). Every component is inspected BEFORE the path is opened; each link
# is followed ONE hop at a time and its target vetted before the next read,
# so no remote path is ever touched. Reading reparse data is local I/O.
# Kept identical in hash-file.ps1 (tools stay import-free); drift is caught
# by tests/duplication-sync.tests.ps1.
function Get-LinkPolicyError([string]$Full) {
    $cur = $Full.Substring(0, 3)
    foreach ($part in $Full.Substring(3).Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        $cur = [IO.Path]::Combine($cur, $part)
        $hop = $cur
        for ($i = 0; ; $i++) {
            if ($i -ge 16) { return 'network or device path denied by policy' }          # link loop / chain too deep
            try { $attr = [IO.File]::GetAttributes($hop) } catch { return $null }        # missing: 'file not found' below
            if (-not ($attr -band [IO.FileAttributes]::ReparsePoint)) { break }
            $fsi = if ($attr -band [IO.FileAttributes]::Directory) { [IO.DirectoryInfo]::new($hop) } else { [IO.FileInfo]::new($hop) }
            try { $t = $fsi.ResolveLinkTarget($false) } catch { return 'network or device path denied by policy' }
            if ($null -eq $t) { break }                                                   # non-link reparse (cloud file, dedup, app exec link)
            $tf = $t.FullName
            if ($tf -match '^[A-Za-z]:\\') {
                try { $dt = [IO.DriveInfo]::new($tf.Substring(0, 1)).DriveType } catch { $dt = 'Unknown' }
                if ("$dt" -in 'Network', 'NoRootDirectory', 'Unknown') { return 'network or device path denied by policy' }
            }
            elseif ($tf -notmatch '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\') { return 'network or device path denied by policy' }
            if ($tf -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { return 'path denied by policy' }
            $hop = $tf
        }
    }
    return $null
}
$linkErr = Get-LinkPolicyError $Path
if ($linkErr) { Out-Result @{ error = $linkErr } }
if (-not (Test-Path -LiteralPath $Path -PathType Leaf))  { Out-Result @{ error = 'file not found' } }

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$chain = @()
if ($sig.SignerCertificate) {
    # subject chain for context (subjects only, no key material)
    $chain = @($sig.SignerCertificate.Subject, $sig.SignerCertificate.Issuer)
}
Out-Result @{
    path         = $Path
    status       = "$($sig.Status)"          # Valid | NotSigned | HashMismatch | ...
    status_msg   = "$($sig.StatusMessage)"
    signer_chain = $chain
    is_os_binary = [bool]$sig.IsOSBinary
    # MSIX/AppX context: NotSigned is EXPECTED there (package-signed, not
    # Authenticode) - the Tier-2 prompt handles this; we only report the fact.
    msix_context = ($Path -match '(?i)\\WindowsApps\\')
}
