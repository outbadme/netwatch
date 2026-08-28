# check-signature.ps1 — Tier-2 MCP tool backend. READ-ONLY.
# pwsh 7 MANDATORY: on this machine PS 5.1 silently fails to load
# Microsoft.PowerShell.Security -> Get-AuthenticodeSignature false "all clear".
# Output: single JSON object on stdout.

#Requires -Version 7
param([Parameter(Mandatory)] [string]$Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

# --- input validation (non-negotiable, model-independent) --------------------
if (-not [IO.Path]::IsPathRooted($Path))            { Out-Result @{ error = 'path must be absolute' } }
if ($Path -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { Out-Result @{ error = 'path denied by policy' } }
if (-not (Test-Path -LiteralPath $Path -PathType Leaf))  { Out-Result @{ error = 'file not found' } }

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$chain = @()
if ($sig.SignerCertificate) {
    # walk subject chain for context (issuer chain subjects only, no key material)
    $c = $sig.SignerCertificate
    $chain = @($c.Subject, $c.Issuer)
}
Out-Result @{
    path         = $Path
    status       = "$($sig.Status)"          # Valid | NotSigned | HashMismatch | ...
    status_msg   = "$($sig.StatusMessage)"
    signer_chain = $chain
    is_os_binary = ($sig.IsOSBinary ?? $false)
    # MSIX/AppX context: NotSigned is EXPECTED there (package-signed, not
    # Authenticode) — the Tier-2 prompt handles this; we only report the fact.
    msix_context = ($Path -match '(?i)\\WindowsApps\\')
}
