# hash-file.ps1 - Tier-2 MCP tool backend. READ-ONLY. JSON on stdout.
# Comparison against vendor/upstream hashes is Tier-3 (human) work - this
# tool only produces the local fact.

#Requires -Version 7.6
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

# Reparse points (symlink/junction) on a local drive can lead to a UNC share
# or into Downloads - the string checks above never see the target (review
# finding). Every component is inspected BEFORE the path is opened; each link
# is followed ONE hop at a time and its target vetted before the next read,
# so no remote path is ever touched. Reading reparse data is local I/O.
# Kept identical in check-signature.ps1 (tools stay import-free); drift is
# caught by tests/duplication-sync.tests.ps1.
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

$item = Get-Item -LiteralPath $Path
Out-Result @{
    path           = $Path
    sha256         = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes     = $item.Length
    last_write_utc = $item.LastWriteTimeUtc.ToString('o')
}
