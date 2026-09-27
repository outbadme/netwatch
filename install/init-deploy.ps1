# init-deploy.ps1 - generates the machine-specific runtime artifacts that the
# repo cannot carry (absolute paths): config/netwatch.config.json and
# src/tier2/mcp-config.json; creates the state root tree and seeds the live
# whitelist. Idempotent; safe without admin. Run once at deploy and after
# moving the repo.
# Params exist for tests only - production runs take the defaults, except
# -ResetTrust (DECISIONS D12): drops every trust decision an EXISTING
# deployment accumulated - live whitelist, suppression cache (prior CLEAN
# verdicts), proposals, classify.browser_attributed_ok and machine_notes in
# the generated config. Each file is first copied to <name>.pre-reset-<utc>.
# Use it on any install that ran on a machine you no longer trust.

#Requires -Version 7.6
param(
    [string]$StateRoot = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch'),
    [string]$ConfigOut,
    [string]$McpConfigOut,
    [switch]$Force,
    [switch]$ResetTrust
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

# --- trust reset (explicit only) ----------------------------------------------
$wlLive = Join-Path $StateRoot 'whitelist.json'
if ($ResetTrust) {
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    foreach ($f in @($wlLive, (Join-Path $StateRoot 'state\suppression.json'), (Join-Path $StateRoot 'state\proposals.jsonl'))) {
        if (Test-Path -LiteralPath $f) {
            Copy-Item -LiteralPath $f -Destination "$f.pre-reset-$stamp"
            Remove-Item -LiteralPath $f
            Write-Host "trust reset: $f (backup: $f.pre-reset-$stamp)"
        }
    }
    if (Test-Path -LiteralPath $ConfigOut) {
        Copy-Item -LiteralPath $ConfigOut -Destination "$ConfigOut.pre-reset-$stamp"
        $old = Get-Content -LiteralPath $ConfigOut -Raw | ConvertFrom-Json
        Write-Host "trust reset: browser_attributed_ok [$(@($old.classify.browser_attributed_ok) -join ', ')] -> []; machine_notes cleared (backup: $ConfigOut.pre-reset-$stamp)"
        $old.classify | Add-Member -NotePropertyName browser_attributed_ok -NotePropertyValue @() -Force
        $old.classify | Add-Member -NotePropertyName machine_notes -NotePropertyValue @() -Force
        $old | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ConfigOut -Encoding utf8
    }
}

# --- live whitelist seed (never overwrites an existing live copy) ------------
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

# --- mcp-config.json (absolute server AND node paths) --------------------------
$mcp = [ordered]@{
    mcpServers = [ordered]@{
        netwatch = [ordered]@{
            type    = 'stdio'
            # absolute, resolved once at deploy (TIER2-CONTRACT 2): a node shim
            # earlier in the Tier-2 child's PATH must not run the MCP server
            command = (Get-Command node -ErrorAction Stop).Source
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
