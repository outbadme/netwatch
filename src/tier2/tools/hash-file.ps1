# hash-file.ps1 - Tier-2 MCP tool backend. READ-ONLY. JSON on stdout.
# Comparison against vendor/upstream hashes is Tier-3 (human) work - this
# tool only produces the local fact.

#Requires -Version 7
param([Parameter(Mandatory)] [string]$Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 4; exit 0 }

if (-not [IO.Path]::IsPathRooted($Path))                 { Out-Result @{ error = 'path must be absolute' } }
# Local drive-letter paths only (UNC/device/mapped-network paths = SMB egress
# + NTLM leak; see check-signature.ps1). Raw string first, before any I/O.
if ($Path -notmatch '^[A-Za-z]:[\\/]')                  { Out-Result @{ error = 'network or device path denied by policy' } }
# Normalize BEFORE the deny check (forward slashes, dot segments, 8.3 names).
try { $Path = [IO.Path]::GetFullPath($Path) } catch { Out-Result @{ error = 'path not normalizable' } }
if ($Path -notmatch '^[A-Za-z]:\\')                     { Out-Result @{ error = 'network or device path denied by policy' } }
if ($Path -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { Out-Result @{ error = 'path denied by policy' } }
try { $driveType = [IO.DriveInfo]::new($Path.Substring(0, 1)).DriveType } catch { $driveType = 'Unknown' }
if ("$driveType" -in 'Network', 'NoRootDirectory', 'Unknown') { Out-Result @{ error = 'network or device path denied by policy' } }
if (-not (Test-Path -LiteralPath $Path -PathType Leaf))  { Out-Result @{ error = 'file not found' } }

$item = Get-Item -LiteralPath $Path
Out-Result @{
    path           = $Path
    sha256         = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes     = $item.Length
    last_write_utc = $item.LastWriteTimeUtc.ToString('o')
}
