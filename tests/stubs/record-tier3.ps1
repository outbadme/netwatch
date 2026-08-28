# record-tier3.ps1 - recording stand-in for launch-tier3.ps1: dumps its argv
# to RECORD_TIER3_FILE so escalate tests can assert the handoff contract.
param(
    [string]$SessionId,
    [Parameter(Mandatory)] [string]$Reason,
    [Parameter(Mandatory)] [string]$AlarmFile,
    [Parameter(Mandatory)] [string]$ClaudeExe,
    [Parameter(Mandatory)] [string]$StateRoot,
    [string]$Keys
)
@{
    session_id = $SessionId
    reason     = $Reason
    alarm_file = $AlarmFile
    claude_exe = $ClaudeExe
    state_root = $StateRoot
    keys       = $Keys
} | ConvertTo-Json | Set-Content -LiteralPath $env:RECORD_TIER3_FILE
