# tier3win.psm1 - Tier-3 window placement helpers (task
# docs/plans/TIER3-IDLE-CLOSE-20260828.md): park the investigation window at
# the top-right corner of the RIGHTMOST screen so it is visible but never in
# the way. Best-effort by contract: every failure returns $false.
#
# Why self-positioning: on this machine Start-Process pwsh windows are hosted
# by the default terminal, and the launched process's MainWindowHandle stays
# zero - the launcher cannot find the window from outside. A conhost-hosted
# pwsh payload, however, CAN move its own console window via
# GetConsoleWindow + MoveWindow (proven live 2026-08-28, winpos probe).

Add-Type -AssemblyName System.Windows.Forms

if (-not ('Win32Move' -as [type])) {
    $src = @'
using System;
using System.Runtime.InteropServices;
public static class Win32Move {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
    Add-Type -TypeDefinition $src
}

function Get-RightmostScreen {
    # Screen whose left edge is furthest right (the only screen, if just one).
    return @([System.Windows.Forms.Screen]::AllScreens |
        Sort-Object { $_.Bounds.X } | Select-Object -Last 1)[0]
}

function Get-WindowRect {
    param([Parameter(Mandatory)] [IntPtr]$Handle)
    $r = New-Object Win32Move+RECT
    if (-not [Win32Move]::GetWindowRect($Handle, [ref]$r)) { return $null }
    return $r
}

function Move-OwnConsoleWindowTopRight {
    # Called from INSIDE the tier-3 payload pwsh. Moves its own console
    # window to the rightmost screen's top-right corner. $false on any
    # failure (no console window under the host, pinvoke refused) - callers
    # must ignore the return value; placement is cosmetic.
    param(
        [int]$Width = 1100,
        [int]$Height = 750
    )
    try {
        $h = [Win32Move]::GetConsoleWindow()
        if ($h -eq [IntPtr]::Zero) { return $false }
        $screen = Get-RightmostScreen
        $x = $screen.Bounds.Right - $Width
        $y = $screen.Bounds.Top
        return [bool][Win32Move]::MoveWindow($h, $x, $y, $Width, $Height, $true)
    } catch {
        return $false
    }
}

Export-ModuleMember -Function Get-RightmostScreen, Get-WindowRect, Move-OwnConsoleWindowTopRight
