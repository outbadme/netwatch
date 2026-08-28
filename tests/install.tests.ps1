# install.tests.ps1 - init-deploy generation (into a test root) and
# protect-keys DPAPI round-trip. register-task/enable-etw are operator-run
# machine changes: reviewed, not executed (operator-run at deploy time).
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$initDeploy  = Resolve-Path "$PSScriptRoot\..\install\init-deploy.ps1"
$protectKeys = Resolve-Path "$PSScriptRoot\..\install\protect-keys.ps1"

$root = New-TestStateRoot
try {
    $cfgOut = Join-Path $root 'generated-config.json'
    $mcpOut = Join-Path $root 'generated-mcp-config.json'

    & pwsh -NoProfile -File $initDeploy -StateRoot $root -ConfigOut $cfgOut -McpConfigOut $mcpOut | Out-Null
    Assert-Equal 0 $LASTEXITCODE 'init-deploy succeeded'
    foreach ($d in 'state', 'logs', 'escalations', 'alarms') {
        Assert-True (Test-Path (Join-Path $root $d)) "state subdir $d"
    }
    Assert-True (Test-Path (Join-Path $root 'whitelist.json')) 'live whitelist seeded'

    # generated config loads through the real loader
    Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
    $cfg = Get-NetwatchConfig -Path $cfgOut
    Assert-Equal $root $cfg.paths.state_root 'state_root in generated config'
    Assert-Equal $script:RepoRoot $cfg.paths.code_root 'code_root = repo'
    Assert-True ($cfg.tier2.claude_exe -like '*claude*') 'claude auto-resolved'
    Assert-True ($cfg.sni.tshark_exe -like '*Wireshark*tshark.exe') 'tshark path expanded from percent form'
    Assert-False ($cfg.sni.tshark_exe.Contains('%')) 'no unexpanded vars'

    # mcp config shape
    $mcp = Get-Content $mcpOut -Raw | ConvertFrom-Json
    Assert-Equal 'stdio' $mcp.mcpServers.netwatch.type 'mcp type'
    Assert-Equal 'node' $mcp.mcpServers.netwatch.command 'mcp command via PATH'
    Assert-True (Test-Path $mcp.mcpServers.netwatch.args[0]) 'server.mjs path exists'
    Assert-Equal $root $mcp.mcpServers.netwatch.env.NETWATCH_STATE 'state env wired'
    Assert-True ($mcp.mcpServers.netwatch.env.NETWATCH_PWSH -like '*pwsh.exe') 'pwsh env wired'

    # idempotency: second run leaves existing config alone
    $before = (Get-Item $cfgOut).LastWriteTimeUtc
    Start-Sleep -Milliseconds 100
    & pwsh -NoProfile -File $initDeploy -StateRoot $root -ConfigOut $cfgOut -McpConfigOut $mcpOut | Out-Null
    Assert-Equal $before ((Get-Item $cfgOut).LastWriteTimeUtc) 'existing config untouched without -Force'

    # --- protect-keys round-trip --------------------------------------------
    $dummy = Join-Path $root 'dummy-keys.txt'
    "# comment`nABUSEIPDB_KEY=abuse-dummy-123`nVT_KEY=vt-dummy-456`n" | Set-Content $dummy
    & pwsh -NoProfile -File $protectKeys -EnvFile $dummy -StateRoot $root -DeleteSource | Out-Null
    Assert-Equal 0 $LASTEXITCODE 'protect-keys succeeded'
    Assert-False (Test-Path $dummy) 'plaintext source deleted'
    $datFile = Join-Path $root 'state\apikeys.dat'
    Assert-True (Test-Path $datFile) 'apikeys.dat written'

    $enc = [IO.File]::ReadAllBytes($datFile)
    Assert-False ([Text.Encoding]::UTF8.GetString($enc).Contains('abuse-dummy-123')) 'ciphertext does not contain plaintext'
    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $keys = [Text.Encoding]::UTF8.GetString($dec) | ConvertFrom-Json
    Assert-Equal 'abuse-dummy-123' $keys.abuseipdb 'abuse key round-trip'
    Assert-Equal 'vt-dummy-456' $keys.vt 'vt key round-trip'

    # empty key file rejected
    $empty = Join-Path $root 'empty-keys.txt'
    "ABUSEIPDB_KEY=`n" | Set-Content $empty
    & pwsh -NoProfile -File $protectKeys -EnvFile $empty -StateRoot $root 2>$null | Out-Null
    Assert-True ($LASTEXITCODE -ne 0) 'empty key file rejected'

    # --- verify-http80-attribution: evidence must match source WITHIN one
    # connection. False-PASS reproduced 2026-08-27: Select-String counted
    # per-line hits of EITHER pattern, and the control host alone occupies two
    # pretty-printed packet lines (key + attribution.domain), reaching the
    # >=2 threshold with source dns-ip and no http-host at all. -------------
    $verify = Resolve-Path "$PSScriptRoot\..\install\verify-http80-attribution.ps1"
    $scanRoot = Join-Path $root 'scan-root'
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $scanRoot 'escalations')
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $scanRoot 'logs')
    @{ connections = @(@{ key = 'pwsh|yr1.c.lencr.org|80'
                          attribution = @{ source = 'dns-ip'; domain = 'yr1.c.lencr.org' } }) } |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $scanRoot 'escalations\fake1-packet.json')
    & pwsh -NoProfile -File $verify -ScanOnly -StateRoot $scanRoot 2>$null | Out-Null
    Assert-Equal 2 $LASTEXITCODE 'dns-ip packet is NOT http-host evidence (false-PASS regression)'
    @{ connections = @(@{ key = 'pwsh|yr1.c.lencr.org|80'
                          attribution = @{ source = 'http-host'; domain = 'yr1.c.lencr.org' } }) } |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $scanRoot 'escalations\fake2-packet.json')
    & pwsh -NoProfile -File $verify -ScanOnly -StateRoot $scanRoot | Out-Null
    Assert-Equal 0 $LASTEXITCODE 'http-host packet accepted as evidence'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
