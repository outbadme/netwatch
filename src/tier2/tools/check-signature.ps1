# check-signature.ps1 - Tier-2 MCP tool backend. READ-ONLY.
# pwsh 7 MANDATORY: on this machine PS 5.1 silently fails to load
# Microsoft.PowerShell.Security -> Get-AuthenticodeSignature false "all clear".
# Output: single JSON object on stdout.

#Requires -Version 7
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
