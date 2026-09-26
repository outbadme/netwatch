# check-signature.ps1 - Tier-2 MCP tool backend. READ-ONLY.
# pwsh 7 MANDATORY: on this machine PS 5.1 silently fails to load
# Microsoft.PowerShell.Security -> Get-AuthenticodeSignature false "all clear".
# Output: single JSON object on stdout.

#Requires -Version 7.6
param([Parameter(Mandatory)] [string]$Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

# --- path policy (non-negotiable, model-independent) -------------------------
# Resolve-PolicyPath is shared VERBATIM with hash-file.ps1 (tools stay
# import-free; tests/duplication-sync.tests.ps1 fails on drift). It returns
# @{ path = <OS-verified final path> } or @{ error = <reason> }.
# Why it is this involved (four independent reviews, 2026-09-26): every
# string check on the INPUT is defeatable - a link inside a link target, a
# junction onto a profile (C:\a\Downloads with C:\a -> C:\Users\x), '..' in a
# link target, 8.3 names, trailing dots, subst drives, NTFS streams. So:
#  1. cheap string gates on the input: local drive letter only, no ':' stream
#     (volume-GUID link targets, \\?\Volume{..}, fail this gate too - denied);
#  2. a LINK-FREE path is computed component by component. Each reparse point
#     is resolved one hop from its local reparse data (no I/O through it); the
#     target is normalized and the walk RESTARTS on target + remaining
#     components. No path with an unvetted link in it ever reaches the OS, so
#     the check itself cannot open an SMB session;
#  3. the file is opened for ATTRIBUTES only (no content read) and the OS's own
#     final name (GetFinalPathNameByHandle: long names, links and subst drives
#     resolved) is vetted once more. The tool then works on that final name.
# A segment ending in '.' or ' ' is refused: Win32 trims those only from the
# LAST segment, so checking a prefix would vet a different entry than the one
# the full path later traverses.
# Residual (all need code already running as this user): a directory on the
# path swapped for a link between the walk and step 3, or between step 3 and
# the tool's own open; a subst drive whose target is itself a link (the walk
# starts below the drive letter).
function Resolve-PolicyPath([string]$InputPath) {
    $netErr = 'network or device path denied by policy'
    $isDownloads = { param($p) $p -match '(?i)\\Users\\[^\\]+\\Downloads(\\|:|$)' }
    $isLocalDrive = {
        param($p)
        if ($p -notmatch '^[A-Za-z]:\\') { return $false }
        try { $dt = [IO.DriveInfo]::new($p.Substring(0, 1)).DriveType } catch { return $false }
        return ("$dt" -notin 'Network', 'NoRootDirectory', 'Unknown')   # mapped drive = SMB behind a letter
    }
    if (-not [IO.Path]::IsPathRooted($InputPath)) { return @{ error = 'path must be absolute' } }
    # raw string first, before any filesystem call: \\host\share, \\?\UNC\...,
    # //host/share and device paths never get further
    if ($InputPath -notmatch '^[A-Za-z]:[\\/]') { return @{ error = $netErr } }
    try { $p = [IO.Path]::GetFullPath($InputPath) } catch { return @{ error = 'path not normalizable' } }
    $streamErr = 'alternate data stream denied by policy'
    for ($restart = 0; ; $restart++) {
        if ($restart -ge 32) { return @{ error = $netErr } }              # link loop / chain too deep
        if ($p.IndexOf(':', 2) -ge 0) { return @{ error = $streamErr } }  # input and every link target
        if ($p -match '[. ](\\|$)') { return @{ error = 'trailing dot or space in a path segment denied by policy' } }
        if (-not (& $isLocalDrive $p)) { return @{ error = $netErr } }
        if (& $isDownloads $p) { return @{ error = 'path denied by policy' } }
        [string[]]$parts = $p.Substring(3).Split('\', [StringSplitOptions]::RemoveEmptyEntries)
        $cur = $p.Substring(0, 3)
        $relinked = $false
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $cur = [IO.Path]::Combine($cur, $parts[$i])
            try { $attr = [int][IO.File]::GetAttributes($cur) }
            catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { return @{ error = 'file not found' } }
            catch { return @{ error = 'path not inspectable - denied by policy' } }   # never "could not check" -> allowed
            # 0x1000 OFFLINE, 0x40000 RECALL_ON_OPEN, 0x400000 RECALL_ON_DATA_ACCESS:
            # cloud placeholders download their content when read (egress)
            if ($attr -band 0x441000) { return @{ error = 'cloud placeholder denied by policy' } }
            if (-not ($attr -band 0x400)) { continue }                          # not a reparse point
            $fsi = if ($attr -band 0x10) { [IO.DirectoryInfo]::new($cur) } else { [IO.FileInfo]::new($cur) }
            try { $t = $fsi.ResolveLinkTarget($false) } catch { return @{ error = $netErr } }
            if ($null -eq $t) { continue }                                      # non-link reparse (dedup, app exec alias): local data
            try { $tf = [IO.Path]::GetFullPath($t.FullName) } catch { return @{ error = $netErr } }   # '..' in a target
            [string[]]$rest = if ($i + 1 -lt $parts.Count) { $parts[($i + 1)..($parts.Count - 1)] } else { @() }
            $p = [IO.Path]::Combine([string[]](@($tf) + $rest))
            $relinked = $true
            break
        }
        if (-not $relinked) { break }
    }

    if (-not ('NwPathNative' -as [type])) {
        Add-Type -Language CSharp @'
using System;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class NwPathNative {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);
    // access 0 = attributes only (no content read); share read|write|delete;
    // OPEN_EXISTING; BACKUP_SEMANTICS so directories open too.
    // flags 0 = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
    public static string FinalPath(string path) {
        using (SafeFileHandle h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (h.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            StringBuilder sb = new StringBuilder(32768);
            uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (n == 0 || n >= sb.Capacity) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return sb.ToString();
        }
    }
}
'@
    }
    # \\?\ : $p is already normalized; the prefix only lifts MAX_PATH
    try { $final = [NwPathNative]::FinalPath('\\?\' + $p) } catch { return @{ error = 'path not inspectable - denied by policy' } }
    if ($final.StartsWith('\\?\UNC\')) { return @{ error = $netErr } }
    if ($final.StartsWith('\\?\')) { $final = $final.Substring(4) }
    if ($final.IndexOf(':', 2) -ge 0) { return @{ error = $streamErr } }
    if (-not (& $isLocalDrive $final)) { return @{ error = $netErr } }
    if (& $isDownloads $final) { return @{ error = 'path denied by policy' } }
    if (-not (Test-Path -LiteralPath $final -PathType Leaf)) { return @{ error = 'file not found' } }
    return @{ path = $final }
}
$resolved = Resolve-PolicyPath $Path
if ($resolved.ContainsKey('error')) { Out-Result @{ error = $resolved.error } }
$Path = $resolved.path

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
