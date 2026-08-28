# mcp-server.tests.ps1 - integration: real node MCP server over stdio via the
# minimal JSON-RPC test client. Exercises tools/list, tools/call relaying to
# the pwsh tool backends, and the per-call timeout kill.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

# Public mirror / fresh clone: node_modules is gitignored (npm ci installs it),
# so the integration test cannot run there. The PRIVATE repo has deps
# installed and always exercises this file for real. Skip loudly, not silently.
if (-not (Test-Path "$PSScriptRoot\..\src\tier2\mcp-server\node_modules")) {
    Write-Host 'NOTE: mcp-server node_modules not installed (mirror/fresh clone) - skipped; npm ci in src/tier2/mcp-server enables it.'
    exit 0
}

$server = Resolve-Path "$PSScriptRoot\..\src\tier2\mcp-server\server.mjs"
$client = Resolve-Path "$PSScriptRoot\stubs\mcp-client.mjs"

function Invoke-McpClient {
    param([string[]]$ClientArgs)
    $out = & node $client $server @ClientArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "mcp client failed: $out" }
    return ($out -join "`n") | ConvertFrom-Json
}

# --- tools/list: exactly the four tools --------------------------------------
$r = Invoke-McpClient @('list')
Assert-Equal 'netwatch' $r.server 'server name'
Assert-Equal 4 $r.tools.Count 'exactly four tools exposed'
foreach ($t in 'check_signature', 'hash_file', 'check_reputation', 'check_process_lineage') {
    Assert-True ($t -in $r.tools) "tool $t present"
}

# --- tools/call: signature positive control through the full stack -----------
$pwshExe = (Get-Command pwsh).Source
$r = Invoke-McpClient @('call', 'check_signature', (@{ path = $pwshExe } | ConvertTo-Json -Compress))
$sig = $r.text | ConvertFrom-Json
Assert-Equal 'Valid' $sig.status 'signature Valid via MCP stack'

# --- tools/call: reputation guard through the stack --------------------------
$root = New-TestStateRoot
try {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $root 'state')
    $env:NETWATCH_STATE = $root
    try {
        $r = Invoke-McpClient @('call', 'check_reputation', '{"ip":"10.0.0.1"}')
        $rep = $r.text | ConvertFrom-Json
        Assert-Equal 'rfc1918' $rep.refused 'guard refusal relayed via MCP'

        # --- per-call timeout: slow tool killed, tool_failed returned --------
        $toolsDir = Join-Path $root 'slow-tools'
        $null = New-Item -ItemType Directory -Force -Path $toolsDir
        # a check-signature stand-in that sleeps far past the test timeout
        "param([string]`$Path)`nStart-Sleep -Seconds 30`n'{}'" |
            Set-Content (Join-Path $toolsDir 'check-signature.ps1')
        $env:NETWATCH_TOOLS_DIR = $toolsDir
        $env:NETWATCH_TOOL_TIMEOUT_MS = '1500'
        $probe = Join-Path $toolsDir 'probe-target.exe'   # path value only; slow stub ignores it
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-McpClient @('call', 'check_signature', (@{ path = $probe } | ConvertTo-Json -Compress))
        $sw.Stop()
        $res = $r.text | ConvertFrom-Json
        Assert-Equal 'tool_failed' $res.error 'timed-out tool reports tool_failed'
        Assert-True ($sw.Elapsed.TotalSeconds -lt 15) "timeout enforced quickly (took $([int]$sw.Elapsed.TotalSeconds)s)"
    }
    finally {
        Remove-Item Env:NETWATCH_STATE, Env:NETWATCH_TOOLS_DIR, Env:NETWATCH_TOOL_TIMEOUT_MS -ErrorAction SilentlyContinue
    }
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
