# invoke-tier2.ps1 — launch headless Tier-2 claude with hard 3-minute cap.
# Concrete mechanism per DECISIONS.md D3: System.Diagnostics.Process +
# WaitForExit(ms) + Kill($true) (kills the whole descendant tree: claude.exe
# -> node.exe children -> MCP server). pwsh 7 only.
#
# Usage: pwsh -File invoke-tier2.ps1 -PacketPath <escalations\ts-packet.json> `
#          -Config <cfg object path> ; exit codes: 0=verdict written,
#          2=timeout(killed), 3=launch failure, 4=bad output after retry.

param(
    [Parameter(Mandatory)] [string]$PacketPath,
    [Parameter(Mandatory)] [string]$ConfigPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cfg        = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$capMs      = 1000 * $cfg.tier2.wall_clock_cap_sec      # default 180 s
$claudeExe  = [Environment]::ExpandEnvironmentVariables($cfg.tier2.claude_exe)
$codeRoot   = [Environment]::ExpandEnvironmentVariables($cfg.paths.code_root)
$stateRoot  = [Environment]::ExpandEnvironmentVariables($cfg.paths.state_root)
$ts         = [IO.Path]::GetFileName($PacketPath) -replace '-packet\.json$',''
$outDir     = Join-Path $stateRoot 'escalations'

$allowed = @(
    'mcp__netwatch__check_signature'
    'mcp__netwatch__hash_file'
    'mcp__netwatch__check_reputation'
    'mcp__netwatch__check_process_lineage'
) -join ','
$denied = 'Bash,Read,Write,Edit,NotebookEdit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite'

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = $claudeExe
$psi.WorkingDirectory       = $stateRoot            # session files live here, not in repo
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute        = $false
# System prompt: --system-prompt takes a STRING (doc-confirmed; a replace-from-
# file flag is not confirmed) -> load the fixed prompt file here. ArgumentList
# passes it as one argv entry, no shell quoting involved.
$sysPrompt = Get-Content (Join-Path $codeRoot 'src\tier2\system-prompt.md') -Raw
foreach ($a in @(
    '-p', 'Analyze the escalation packet provided on stdin per your system prompt.',
    '--model', $cfg.tier2.model,
    '--output-format', 'json',
    '--system-prompt', $sysPrompt,
    '--mcp-config',    (Join-Path $codeRoot 'src\tier2\mcp-config.json'),
    '--strict-mcp-config',
    '--permission-mode', 'dontAsk',
    '--allowedTools',    $allowed,
    '--disallowedTools', $denied,
    '--max-turns', "$($cfg.tier2.max_turns)"
)) { $psi.ArgumentList.Add($a) }
# API keys for the MCP tools: injected into env from DPAPI store, never argv.
# $psi.Environment['ABUSEIPDB_KEY'] = <Unprotect state\apikeys.dat>  # TODO
# $psi.Environment['VT_KEY']        = <Unprotect state\apikeys.dat>  # TODO
$psi.Environment['NETWATCH_STATE'] = $stateRoot

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi
try { $null = $proc.Start() } catch { exit 3 }                    # F3

# Async drains BEFORE stdin write — avoids pipe-buffer deadlock on big output.
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()

$proc.StandardInput.Write((Get-Content $PacketPath -Raw))          # packet = prompt body
$proc.StandardInput.Close()

if (-not $proc.WaitForExit($capMs)) {
    # HARD CAP HIT: kill entire tree (claude + node children + MCP server).
    # Kill([bool]entireProcessTree) is .NET Core 3.0+; pwsh 7 = .NET 8.
    try { $proc.Kill($true) } catch { }
    $proc.WaitForExit()                                            # reap
    Set-Content (Join-Path $outDir "$ts-stderr.txt") $stderrTask.Result
    exit 2                                                         # F1 -> caller triggers Tier 3
}

$stdout = $stdoutTask.Result
Set-Content (Join-Path $outDir "$ts-stdout.json") $stdout
Set-Content (Join-Path $outDir "$ts-stderr.txt")  $stderrTask.Result

# Parse: claude JSON envelope -> {result, session_id, ...}; verdict JSON is in .result
try {
    $envelope = $stdout | ConvertFrom-Json
    $verdict  = $envelope.result | ConvertFrom-Json
    # TODO: JSON-schema validation (verdict.schema.json) + key cross-check vs
    # packet (F24): every packet key answered, no unknown keys, verdict==ALARM
    # if any assessment==suspicious.
} catch { exit 4 }                                                 # F2 -> caller retries once

[pscustomobject]@{
    session_id = $envelope.session_id                              # needed by Tier 3 (--resume)
    verdict    = $verdict
} | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $outDir "$ts-verdict.json")
exit 0
