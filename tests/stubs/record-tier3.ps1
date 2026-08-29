# record-tier3.ps1 - recording stand-in for launch-tier3.ps1: dumps its argv
# to RECORD_TIER3_FILE so escalate tests can assert the handoff contract.
param(
    [string]$SessionId,
    [Parameter(Mandatory)] [string]$Reason,
    [Parameter(Mandatory)] [string]$AlarmFile,
    [Parameter(Mandatory)] [string]$ClaudeExe,
    [Parameter(Mandatory)] [string]$StateRoot,
    [string]$Keys,
    # tier3 window lifecycle args (TIER3-IDLE-CLOSE-20260828); recorded so the
    # escalate tests can assert the handoff contract end-to-end
    [int]$IdleCloseMin = 5,
    [int]$WindowWidthPx = 1100,
    [int]$WindowHeightPx = 750,
    [string]$ReportDir = ''
)
@{
    session_id = $SessionId
    reason     = $Reason
    alarm_file = $AlarmFile
    claude_exe = $ClaudeExe
    state_root = $StateRoot
    keys       = $Keys
    idle_close_min   = $IdleCloseMin
    window_width_px  = $WindowWidthPx
    window_height_px = $WindowHeightPx
    report_dir       = $ReportDir
} | ConvertTo-Json | Set-Content -LiteralPath $env:RECORD_TIER3_FILE
