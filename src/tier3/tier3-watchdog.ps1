# tier3-watchdog.ps1 - hidden companion of a Tier-3 investigation window
# (task docs/plans/TIER3-IDLE-CLOSE-20260828.md, operator request 2026-08-28).
#
# Runs as a plain pwsh child of launch-tier3.ps1 (NOT a claude session, so
# the PreToolUse jail hooks do not apply - the report dir is deliberately
# outside the jail roots and the agent inside the window could not write it).
#
# Behavior:
#   - poll every 15 s;
#   - target window process gone        -> write report (operator closed it
#     or the agent finished), exit;
#   - global input idle >= threshold    -> kill the window's process tree,
#     write report (idle auto-close), exit;
#   - idle sensor broken                -> fail OPEN (never close on a broken
#     sensor), WARN to op-log, keep watching the target's lifetime only.
#
# Test seam: env NETWATCH_TEST_IDLE_MS overrides the measured idle.

#Requires -Version 7
param(
    [Parameter(Mandatory)] [int]$TargetPid,
    [string]$Keys = '',
    [string]$PacketPath = '',
    [string]$SessionId = '',
    [Parameter(Mandatory)] [string]$OpenedUtc,
    [Parameter(Mandatory)] [int]$IdleThresholdMs,
    [Parameter(Mandatory)] [string]$ReportDir,
    [string]$OpLogDir = ''                  # optional: <state>\logs for WARN lines
)
Set-StrictMode -Version Latest

function Get-InputIdleMs {
    if ($env:NETWATCH_TEST_IDLE_MS) { return [uint32]$env:NETWATCH_TEST_IDLE_MS }
    if (-not ('IdleTime' -as [type])) {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class IdleTime {
    [StructLayout(LayoutKind.Sequential)]
    public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    public static uint GetIdleMs() {
        LASTINPUTINFO lii = new LASTINPUTINFO();
        lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
        if (!GetLastInputInfo(ref lii)) throw new InvalidOperationException("GetLastInputInfo failed");
        return unchecked(((uint)Environment.TickCount) - lii.dwTime);
    }
}
'@
        Add-Type -TypeDefinition $src
    }
    return [IdleTime]::GetIdleMs()
}

function Write-OpWarn([string]$msg) {
    if (-not $OpLogDir) { return }
    try {
        $line = "{0} WARN tier3-watchdog: {1}" -f ([datetime]::UtcNow.ToString('o')), $msg
        $f = Join-Path $OpLogDir ('netwatch-' + [datetime]::UtcNow.ToString('yyyyMMdd') + '.log')
        Add-Content -LiteralPath $f -Value $line -Encoding utf8
    } catch { }
}

function Write-CloseReport {
    param([Parameter(Mandatory)] [string]$CloseReason)
    $null = New-Item -ItemType Directory -Force -Path $ReportDir
    $verdict = ''
    if ($PacketPath) {
        $v1 = $PacketPath -replace '-packet\.json$', '-verdict.json'
        $v2 = $PacketPath -replace '-packet\.json$', '-verdict-tier3.json'
        foreach ($v in @($v1, $v2)) { if (Test-Path -LiteralPath $v) { $verdict = $v; break } }
    }
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $body = @(
        "# Tier-3 window closed"
        ""
        "- closed_utc: $([datetime]::UtcNow.ToString('o'))"
        "- opened_utc: $OpenedUtc"
        "- close_reason: $CloseReason"
        "- keys: $(if ($Keys) { $Keys } else { '(none recorded)' })"
        "- packet: $(if ($PacketPath) { $PacketPath } else { '(unknown)' })"
        "- tier2_session_id (reference only): $(if ($SessionId) { $SessionId } else { '(none)' })"
        "- verdict file: $(if ($verdict) { $verdict } else { 'none yet' })"
        ""
        "The session transcript persists; the investigation can be reopened"
        "from the packet above. Deleting the alarm's open.marker re-enables"
        "escalation for these keys."
    ) -join "`n"
    $safe = ($Keys -replace '[^\w\.-]', '_')
    if ($safe.Length -gt 40) { $safe = $safe.Substring(0, 40) }
    $name = "{0}Z-tier3-{1}.md" -f $stamp, $(if ($safe) { $safe } else { 'window' })
    $out = Join-Path $ReportDir $name
    [IO.File]::WriteAllText($out, $body, [Text.UTF8Encoding]::new($false))
    return $out
}

$idleSensorOk = $true
try { $null = Get-InputIdleMs } catch {
    $idleSensorOk = $false
    Write-OpWarn "GetLastInputInfo unavailable ($($_.Exception.Message)) - idle auto-close disabled, lifetime watch only"
}

while ($true) {
    $alive = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
    if (-not $alive) {
        $null = Write-CloseReport -CloseReason 'closed by operator or agent exited'
        exit 0
    }
    if ($IdleThresholdMs -gt 0 -and $idleSensorOk) {
        $idle = Get-InputIdleMs
        if ($idle -ge $IdleThresholdMs) {
            & taskkill /PID $TargetPid /T /F 2>&1 | Out-Null
            $null = Write-CloseReport -CloseReason "operator idle auto-close (idle ${idle}ms >= threshold ${IdleThresholdMs}ms)"
            exit 0
        }
    }
    Start-Sleep -Seconds 15
}
