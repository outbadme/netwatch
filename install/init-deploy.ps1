# init-deploy.ps1 - generates the machine-specific runtime artifacts that the
# repo cannot carry (absolute paths): config/netwatch.config.json and
# src/tier2/mcp-config.json; creates the state root tree and seeds the live
# whitelist. Idempotent; safe without admin. Run once at deploy and after
# moving the repo.
# Params exist for tests only - production runs take the defaults.

#Requires -Version 7.6
param(
    [string]$StateRoot = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch'),
    [string]$ConfigOut,
    [string]$McpConfigOut,
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $ConfigOut)    { $ConfigOut    = Join-Path $repoRoot 'config\netwatch.config.json' }
if (-not $McpConfigOut) { $McpConfigOut = Join-Path $repoRoot 'src\tier2\mcp-config.json' }

# --- state root tree ---------------------------------------------------------
foreach ($d in '', 'state', 'logs', 'escalations', 'alarms') {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $StateRoot $d)
}

# --- live whitelist seed (never overwrites an existing live copy) ------------
$wlLive = Join-Path $StateRoot 'whitelist.json'
if (-not (Test-Path -LiteralPath $wlLive)) {
    Copy-Item (Join-Path $repoRoot 'config\whitelist.seed.json') $wlLive
    Write-Host "whitelist seeded -> $wlLive"
}

# --- netwatch.config.json ----------------------------------------------------
if ((Test-Path -LiteralPath $ConfigOut) -and -not $Force) {
    Write-Host "config exists, left untouched: $ConfigOut (use -Force to regenerate)"
}
else {
    $cfg = Get-Content (Join-Path $repoRoot 'config\netwatch.config.example.json') -Raw | ConvertFrom-Json
    $cfg.paths.state_root = $StateRoot
    $cfg.paths.code_root  = $repoRoot
    $cfg.paths.whitelist  = $wlLive
    $cfg.tier2.claude_exe = 'auto'   # resolve via PATH at load (state.psm1)
    $cfg.sni.tshark_exe   = '%ProgramFiles%\Wireshark\tshark.exe'
    $cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ConfigOut -Encoding utf8
    Write-Host "config written -> $ConfigOut"
}

# --- mcp-config.json (absolute server path; command via PATH) ----------------
$mcp = [ordered]@{
    mcpServers = [ordered]@{
        netwatch = [ordered]@{
            type    = 'stdio'
            command = 'node'
            args    = @((Join-Path $repoRoot 'src\tier2\mcp-server\server.mjs'))
            env     = [ordered]@{
                NETWATCH_STATE = $StateRoot
                NETWATCH_PWSH  = (Get-Command pwsh).Source
            }
        }
    }
}
$mcp | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $McpConfigOut -Encoding utf8
Write-Host "mcp config written -> $McpConfigOut"

# --- sanity: config loads through the real loader ----------------------------
Import-Module (Join-Path $repoRoot 'src\tier1\modules\state.psm1') -Force
$loaded = Get-NetwatchConfig -Path $ConfigOut
Write-Host "config validates: state_root=$($loaded.paths.state_root) claude=$($loaded.tier2.claude_exe)"
