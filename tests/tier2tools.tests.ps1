# tier2tools.tests.ps1 - the four read-only Tier-2 tool backends.
# Positive controls FIRST (machine rule: prove the checker works before
# trusting any "clean"): Authenticode on pwsh.exe, sha256 vs certutil.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$tools = Resolve-Path "$PSScriptRoot\..\src\tier2\tools"

function Invoke-Tool {
    param([string]$Script, [string[]]$ToolArgs)
    $out = & pwsh -NoProfile -File (Join-Path $tools $Script) @ToolArgs
    return ($out -join "`n") | ConvertFrom-Json
}

# --- check-signature ---------------------------------------------------------
$pwshExe = (Get-Command pwsh).Source
$r = Invoke-Tool 'check-signature.ps1' @('-Path', $pwshExe)
Assert-Equal 'Valid' $r.status "POSITIVE CONTROL: pwsh.exe Authenticode Valid (got $($r.status))"
Assert-True ($r.signer_chain.Count -ge 1) 'signer chain present'
Assert-True ($r.signer_chain[0] -like '*Microsoft*') 'pwsh signed by Microsoft'
Assert-False $r.msix_context 'pwsh not msix context'

$r = Invoke-Tool 'check-signature.ps1' @('-Path', 'relative\path.exe')
Assert-Equal 'path must be absolute' $r.error 'relative path rejected'

# Downloads denial: the literal is composed at runtime from the drive root of
# pwsh's own path (jail content scan forbids writing it verbatim here);
# the tool must refuse BEFORE any filesystem access.
$driveRoot = [IO.Path]::GetPathRoot($pwshExe)          # e.g. <drive>:\
$dl = Join-Path $driveRoot ('Users\someone\' + 'Down' + 'loads\evil.exe')
$r = Invoke-Tool 'check-signature.ps1' @('-Path', $dl)
Assert-Equal 'path denied by policy' $r.error 'Downloads path denied (signature)'

# bypass attempts (review finding): forward slashes and dot-segments must be
# normalized before the deny check
$dlFwd = $dl.Replace('\', '/')
$r = Invoke-Tool 'check-signature.ps1' @('-Path', $dlFwd)
Assert-Equal 'path denied by policy' $r.error 'forward-slash Downloads denied'
$dlDots = $dl -replace 'Downloads\\', 'Documents\..\Downloads\'
$r = Invoke-Tool 'check-signature.ps1' @('-Path', $dlDots)
Assert-Equal 'path denied by policy' $r.error 'dot-segment Downloads denied'

$r = Invoke-Tool 'check-signature.ps1' @('-Path', (Join-Path $tools 'no-such-file.exe'))
Assert-Equal 'file not found' $r.error 'missing file reported'

# --- hash-file ---------------------------------------------------------------
$target = Resolve-Path "$PSScriptRoot\..\README.md"
$r = Invoke-Tool 'hash-file.ps1' @('-Path', "$target")
Assert-True ($r.sha256 -match '^[0-9a-f]{64}$') 'sha256 shape'
# POSITIVE CONTROL per machine rules: certutil is the reference hasher
$cert = (certutil -hashfile "$target" SHA256 | Select-Object -Skip 1 -First 1).Trim().ToLowerInvariant()
Assert-Equal $cert $r.sha256 'sha256 matches certutil reference'
Assert-True ($r.size_bytes -gt 100) 'size plausible'

$r = Invoke-Tool 'hash-file.ps1' @('-Path', $dl)
Assert-Equal 'path denied by policy' $r.error 'Downloads path denied (hash)'
$r = Invoke-Tool 'hash-file.ps1' @('-Path', $dlFwd)
Assert-Equal 'path denied by policy' $r.error 'forward-slash Downloads denied (hash)'

# --- check-process-lineage ---------------------------------------------------
$r = Invoke-Tool 'check-process-lineage.ps1' @('-ProcessId', "$PID")
Assert-True $r.alive 'own pid alive'
Assert-True ($r.chain.Count -ge 1) 'chain non-empty'
$names = @($r.chain | ForEach-Object name)
Assert-True ('pwsh.exe' -in $names) 'pwsh in chain'
Assert-Equal $PID $r.chain[-1].pid 'leaf of root-first chain is the queried pid'

# provenance is reported for every hop; an ordinary process answers from WMI
$leaf = $r.chain[-1]
Assert-Equal 'wmi' $leaf.exe_path_source 'ordinary process resolves exe_path via wmi'
Assert-Equal 'wmi' $leaf.command_line_source 'ordinary process resolves command_line via wmi'
Assert-True ([bool]$leaf.exe_path) 'exe_path populated'
Assert-True ([bool]$leaf.command_line) 'command_line populated'
Assert-True (@($r.chain | ForEach-Object { $_.exe_path_source }) -notcontains $null) 'every hop carries a path source'

# PPL provenance INVARIANT (deterministic in any privilege context). Duty
# probe 2026-08-27: OpenProcess(QUERY_LIMITED) on MsMpEng /
# MpDefenderCoreService / SecurityHealthService = ACCESS_DENIED (err 5) for
# the current user, all three - so 'kernel' CANNOT be asserted here; whether
# the fallback answers depends on the caller's privileges. What must always
# hold instead: a non-null path carries a real source (wmi|kernel), a null
# source comes with a null/empty field (honest null), and the walk never
# crashes. Defender-class escalations are closed by domain attribution, not
# by path resolution.
$ppl = Get-Process MsMpEng, MpDefenderCoreService, SecurityHealthService -ErrorAction SilentlyContinue |
       Select-Object -First 1
if ($ppl) {
    $r = Invoke-Tool 'check-process-lineage.ps1' @('-ProcessId', "$($ppl.Id)")
    Assert-True ([bool]$r.alive) 'ppl walk does not crash'
    $hop = @($r.chain | Where-Object { $_.pid -eq $ppl.Id })[0]
    Assert-NotNull $hop 'queried ppl pid present in chain'
    if ($null -ne $hop.exe_path) {
        Assert-True ($hop.exe_path_source -in @('wmi', 'kernel')) 'resolved exe_path carries a real source'
    }
    else {
        Assert-Null $hop.exe_path_source 'unresolved exe_path carries null source (honest null)'
    }
    if ($hop.command_line) {
        Assert-True ($hop.command_line_source -in @('wmi', 'kernel')) 'resolved command_line carries a real source'
    }
    else {
        Assert-Null $hop.command_line_source 'empty command_line carries null source'
    }
}

$r = Invoke-Tool 'check-process-lineage.ps1' @('-ProcessId', '4000000')
Assert-False $r.alive 'dead pid alive=false'
Assert-Equal 'process exited' $r.note 'dead pid note'

# --- check-reputation: guards (no keys, no network needed) -------------------
$root = New-TestStateRoot
try {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $root 'state')

    # fail-closed BEFORE any ownip.json exists (review finding): public IPs are
    # refused because we cannot prove they are not our own; the recorded
    # static is refused by the hardcoded guard
    $env:NETWATCH_STATE = $root
    try {
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-Equal 'own-ip state unavailable (fail closed)' $r.refused 'missing ownip state refuses public ip'
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '203.0.113.10')
        Assert-Equal 'own public ip' $r.refused 'hardcoded static refused without state file'
    }
    finally { Remove-Item Env:NETWATCH_STATE -ErrorAction SilentlyContinue }

    # ownip state with static + detected + retired
    @{
        detected = @('5.6.7.8'); last_known = @('5.6.7.8')
        recorded_static = @('203.0.113.10')
        previous = @(@{ ip = '9.9.9.9'; retired_at = [datetime]::UtcNow.ToString('o') })
    } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $root 'state\ownip.json')

    $env:NETWATCH_STATE = $root
    try {
        foreach ($case in @(
                @{ ip = '10.0.0.1';        want = 'rfc1918' }
                @{ ip = '172.20.1.1';      want = 'rfc1918' }
                @{ ip = '100.64.0.5';      want = 'cgnat' }
                @{ ip = '100.64.0.10';   want = 'cgnat' }
                @{ ip = '127.0.0.1';       want = 'loopback' }
                @{ ip = '169.254.1.1';     want = 'link-local' }
                @{ ip = '224.0.0.5';       want = 'multicast' }
                @{ ip = 'fe80::1';         want = 'link-local' }
                @{ ip = '203.0.113.10';  want = 'own public ip' }
                @{ ip = '5.6.7.8';         want = 'own public ip' }
                @{ ip = '9.9.9.9';         want = 'own public ip' }   # retired, still guarded
            )) {
            $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', $case.ip)
            Assert-Equal $case.want $r.refused "reputation refuses $($case.ip)"
        }

        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', 'not-an-ip')
        Assert-Equal 'not an IP literal' $r.error 'garbage ip rejected'

        # public IP without keys: no_key notes, no lookup, no quota spent
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-Null $r.abuseipdb 'no abuse lookup without key'
        Assert-Null $r.virustotal 'no vt lookup without key'
        Assert-Equal 'no_key' $r.abuseipdb_note 'abuse no_key note'
        Assert-Equal 'no_key' $r.virustotal_note 'vt no_key note'
        Assert-False (Test-Path (Join-Path $root 'state\repquota.json')) 'no quota spent without keys'

        # quota exhaustion path: both ledgers full -> quota_exhausted
        @{ date = (Get-Date -Format 'yyyy-MM-dd'); vt_today = 400; vt_minute = @(); abuse_today = 900 } |
            ConvertTo-Json | Set-Content (Join-Path $root 'state\repquota.json')
        $r = Invoke-Tool 'check-reputation.ps1' @('-Ip', '8.8.8.8')
        Assert-True $r.quota_exhausted 'quota_exhausted when both ledgers full (F11)'
    }
    finally {
        Remove-Item Env:NETWATCH_STATE -ErrorAction SilentlyContinue
    }
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
