# sampling.tests.ps1 - TCP snapshot normalization, PID->image cache,
# direction heuristic, image-gone detection (F14).
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\sampling.psm1" -Force

# --- direction heuristic (pure) ---------------------------------------------
$listen = [System.Collections.Generic.HashSet[int]]::new()
$null = $listen.Add(3389)
Assert-Equal 'inbound' (Get-ConnDirection -LocalPort 3389 -ListenPorts $listen) 'lport in listen set = inbound'
Assert-Equal 'outbound' (Get-ConnDirection -LocalPort 51234 -ListenPorts $listen) 'ephemeral lport = outbound'

# --- live sample -------------------------------------------------------------
$cache = @{}
$sample = @(Get-ConnectionSample -PidCache $cache)
Assert-True ($sample.Count -ge 1) "live sample non-empty (this session has connections; got $($sample.Count))"
$c = $sample[0]
foreach ($k in 'pid', 'name', 'raddr', 'rport', 'laddr', 'lport', 'state', 'direction',
             'image_path', 'image_exists', 'command_line', 'domain', 'attribution_source') {
    Assert-True $c.ContainsKey($k) "normalized conn has key $k"
}

# our own pwsh process should appear in the PID cache after sampling any conn
# owned by it OR we can resolve it directly:
$me = Resolve-ProcessInfo -ProcessId $PID -PidCache $cache
Assert-Equal 'pwsh' $me.name 'own pid resolves to pwsh (lowercase, no .exe)'
Assert-True $me.image_exists 'pwsh image exists'
Assert-True ($me.image_path -like '*pwsh.exe') 'image path plausible'
Assert-NotNull $me.command_line 'command line captured'

# dead pid resolves to unknown, not an exception
$dead = Resolve-ProcessInfo -ProcessId 4000000 -PidCache $cache
Assert-Equal 'unknown' $dead.name 'dead pid name unknown'
Assert-False $dead.image_exists 'dead pid image_exists false'

# --- image-gone (F14) --------------------------------------------------------
$root = New-TestStateRoot
try {
    $tmpExe = Join-Path $root 'ghost.exe'
    'MZ' | Set-Content -LiteralPath $tmpExe
    $conn = @{ image_path = $tmpExe; image_exists = $true }
    Assert-False (Test-ImageGone -Conn $conn) 'image present: not gone'
    Remove-Item $tmpExe
    Assert-True (Test-ImageGone -Conn $conn) 'deleted image detected'
    $noPath = @{ image_path = $null; image_exists = $false }
    Assert-False (Test-ImageGone -Conn $noPath) 'no recorded path: cannot claim gone'
}
finally {
    Remove-TestStateRoot $root
}

# listen ports live: returns a set (may be empty on a locked-down box, but must
# not throw; RDP/tailscale on this machine normally listens)
$ports = Get-ListenPorts
Assert-NotNull $ports 'listen ports set returned'
Write-Host "listen ports observed: $($ports.Count)"

# --- PID-reuse guard: cache pruned to live PIDs (review finding) -------------
$pc = @{ 111 = @{ name = 'ghost' }; 222 = @{ name = 'kept' } }
Sync-PidCache -PidCache $pc -ActivePids @(222)
Assert-False $pc.ContainsKey(111) 'inactive pid dropped from cache'
Assert-True $pc.ContainsKey(222) 'active pid kept'
Sync-PidCache -PidCache $pc -ActivePids @()
Assert-Equal 0 $pc.Count 'empty sample clears cache'

# --- host addresses (both-ends-local input) ----------------------------------
$hostAddrs = Get-HostAddresses
Assert-True ($hostAddrs.Count -ge 1) 'host has at least one address'
Assert-True ($hostAddrs.Contains('127.0.0.1')) 'loopback among host addresses'

Complete-Tests
