# check-process-lineage.ps1 - Tier-2 MCP tool backend. READ-ONLY. JSON stdout.
# Walks pid -> parent -> ... via CIM Win32_Process (max depth 10, cycle guard).

#Requires -Version 7.4
param([Parameter(Mandatory)] [int]$ProcessId)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

# Win32_Process reads BOTH ExecutablePath and CommandLine out of the target's
# PEB, and both come back empty for protected processes (PPL antimalware:
# MsMpEng, MpDefenderCoreService, SecurityHealthService) and some SYSTEM
# services. The kernel keeps its own copies: QueryFullProcessImageName for the
# image, NtQueryInformationProcess(ProcessCommandLineInformation) for the
# command line. CAVEAT (probed 2026-08-27): OpenProcess with
# PROCESS_QUERY_LIMITED_INFORMATION against the PPL antimalware set is
# ACCESS_DENIED (err 5) for an ordinary user on this machine - the fallback
# answers only when the caller's privileges allow the open; otherwise both
# fields stay null with source=null, which the prompt treats as a gap in
# evidence. Defender-class escalations are closed by domain attribution,
# not by path resolution.
function Initialize-NwProcNative {
    if ('NwProcNative' -as [type]) { return }                     # compile only when needed
    Add-Type -Language CSharp @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class NwProcNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder buf, ref uint size);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, uint len, out uint ret);

    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const int  ProcessCommandLineInformation     = 60;            // Win8.1+
    const int  STATUS_INFO_LENGTH_MISMATCH       = unchecked((int)0xC0000004);

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    public static string GetImagePath(int pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero) { return null; }
        try {
            uint cap = 32768;
            StringBuilder sb = new StringBuilder((int)cap);
            if (!QueryFullProcessImageNameW(h, 0, sb, ref cap)) { return null; }
            return sb.ToString(0, (int)cap);
        } finally { CloseHandle(h); }
    }

    public static string GetCommandLine(int pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero) { return null; }
        IntPtr buf = IntPtr.Zero;
        try {
            uint need = 0;
            int st = NtQueryInformationProcess(h, ProcessCommandLineInformation, IntPtr.Zero, 0, out need);
            if ((st != STATUS_INFO_LENGTH_MISMATCH && st != 0) || need == 0) { return null; }
            buf = Marshal.AllocHGlobal((int)need);
            if (NtQueryInformationProcess(h, ProcessCommandLineInformation, buf, need, out need) != 0) { return null; }
            UNICODE_STRING us = (UNICODE_STRING)Marshal.PtrToStructure(buf, typeof(UNICODE_STRING));
            if (us.Buffer == IntPtr.Zero || us.Length == 0) { return null; }
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        } finally {
            if (buf != IntPtr.Zero) { Marshal.FreeHGlobal(buf); }
            CloseHandle(h);
        }
    }
}
'@
}

function Resolve-ImagePath([int]$TargetPid, [string]$WmiPath) {
    if ($WmiPath) { return @{ path = $WmiPath; source = 'wmi' } }
    Initialize-NwProcNative
    $kernelPath = $null
    try { $kernelPath = [NwProcNative]::GetImagePath($TargetPid) } catch { $kernelPath = $null }
    if ($kernelPath) { return @{ path = $kernelPath; source = 'kernel' } }
    return @{ path = $null; source = $null }                      # genuinely unresolvable
}

function Resolve-CommandLine([int]$TargetPid, [string]$WmiCmd) {
    if ($WmiCmd) { return @{ cmd = $WmiCmd; source = 'wmi' } }
    Initialize-NwProcNative
    $kernelCmd = $null
    try { $kernelCmd = [NwProcNative]::GetCommandLine($TargetPid) } catch { $kernelCmd = $null }
    if ($kernelCmd) { return @{ cmd = $kernelCmd; source = 'kernel' } }
    return @{ cmd = ''; source = $null }                          # stays a string for consumers
}

$chain = [System.Collections.Generic.List[object]]::new()
$seen  = [System.Collections.Generic.HashSet[int]]::new()
$cur   = $ProcessId

for ($depth = 0; $depth -lt 10 -and $cur -gt 0; $depth++) {
    if (-not $seen.Add($cur)) { break }                       # PID-reuse cycle guard
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
    if (-not $p) {
        if ($depth -eq 0) { Out-Result @{ alive = $false; note = 'process exited'; chain = @() } }
        break                                                 # parent gone (normal) - stop walk
    }
    $img = Resolve-ImagePath   -TargetPid ([int]$p.ProcessId) -WmiPath ([string]$p.ExecutablePath)
    $cmd = Resolve-CommandLine -TargetPid ([int]$p.ProcessId) -WmiCmd  ([string]$p.CommandLine)
    $chain.Add(@{
        pid                 = $p.ProcessId
        name                = $p.Name
        exe_path            = $img.path
        exe_path_source     = $img.source                     # wmi | kernel | null (null = unreadable in THIS privilege context)
        command_line        = $cmd.cmd                        # DATA for the model, may be hostile text
        command_line_source = $cmd.source                     # same triple; null => genuinely unavailable
        start_time          = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        parent_pid          = $p.ParentProcessId
    })
    $cur = [int]$p.ParentProcessId
}

$chain.Reverse()                                              # root-first
Out-Result @{ alive = $true; chain = $chain }
