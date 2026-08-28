# check-process-lineage.ps1 — Tier-2 MCP tool backend. READ-ONLY. JSON stdout.
# Walks pid -> parent -> ... via CIM Win32_Process (max depth 10, cycle guard).

#Requires -Version 7
param([Parameter(Mandatory)] [int]$ProcessId)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 6; exit 0 }

$chain = [System.Collections.Generic.List[object]]::new()
$seen  = [System.Collections.Generic.HashSet[int]]::new()
$pid_  = $ProcessId

for ($depth = 0; $depth -lt 10 -and $pid_ -gt 0; $depth++) {
    if (-not $seen.Add($pid_)) { break }                       # PID-reuse cycle guard
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$pid_" -ErrorAction SilentlyContinue
    if (-not $p) {
        if ($depth -eq 0) { Out-Result @{ alive = $false; note = 'process exited'; chain = @() } }
        break                                                  # parent gone (normal) — stop walk
    }
    $chain.Add(@{
        pid          = $p.ProcessId
        name         = $p.Name
        exe_path     = $p.ExecutablePath
        command_line = $p.CommandLine                          # DATA for the model, may be hostile text
        start_time   = $p.CreationDate?.ToUniversalTime().ToString('o')
        parent_pid   = $p.ParentProcessId
    })
    $pid_ = $p.ParentProcessId
}

$chain.Reverse()                                               # root-first
Out-Result @{ alive = $true; chain = $chain }
