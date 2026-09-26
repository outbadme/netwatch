# duplication-sync.tests.ps1 - guards the deliberate duplications between the
# import-free Tier-2 tools and Tier 1 against drift. The copies exist on
# purpose (each tool stays independently reviewable, see check-reputation.ps1
# header / TIER2-CONTRACT 1.3); this file makes a one-sided edit fail loudly.
#  1. Resolve-PolicyPath: textually identical in check-signature / hash-file
#     (compared via the PowerShell AST, not grep).
#  2. Ledger mutex name: same derivation in state.psm1 and check-reputation.
#  3. IP lookup guards: NOT textually shared (Tier 1 = netutil/enrich
#     functions, tool = inline code), so parity is checked by BEHAVIOUR - one
#     corpus through both, identical send/refuse decisions and reasons.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$src = Resolve-Path "$PSScriptRoot\..\src"
function Get-Ast([string]$Path) {
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
    Assert-Equal 0 @($errs).Count "parses cleanly: $Path"
    return $ast
}
function Get-FunctionText($Ast, [string]$Name) {
    $f = @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true))
    Assert-Equal 1 $f.Count "exactly one $Name"
    return ($f[0].Extent.Text -replace "`r`n", "`n")
}

# --- 1. Resolve-PolicyPath --------------------------------------------------
$sigAst  = Get-Ast (Join-Path $src 'tier2\tools\check-signature.ps1')
$hashAst = Get-Ast (Join-Path $src 'tier2\tools\hash-file.ps1')
$a = Get-FunctionText $sigAst  'Resolve-PolicyPath'
$b = Get-FunctionText $hashAst 'Resolve-PolicyPath'
Assert-True ($a -ceq $b) 'Resolve-PolicyPath identical in check-signature.ps1 and hash-file.ps1'

# --- 2. ledger mutex name derivation ------------------------------------------
function Get-MutexExpr($Ast) {
    $e = @($Ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                $n.Left -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $n.Left.Value -eq 'netwatch-repquota-' }, $true))
    Assert-Equal 1 $e.Count 'exactly one mutex-name expression'
    # variable names are case-insensitive in PowerShell ($LedgerFile vs
    # $ledgerFile); whitespace/line breaks carry no meaning
    return (($e[0].Extent.Text -replace '\s+', '').ToLowerInvariant())
}
$repAst   = Get-Ast (Join-Path $src 'tier2\tools\check-reputation.ps1')
$stateAst = Get-Ast (Join-Path $src 'tier1\modules\state.psm1')
Assert-Equal (Get-MutexExpr $stateAst) (Get-MutexExpr $repAst) 'mutex name derivation identical in state.psm1 and check-reputation.ps1'

# --- 3. IP guard parity: Tier 1 vs check-reputation ---------------------------
Import-Module (Join-Path $src 'tier1\modules\enrich.psm1') -Force
$static = '203.0.113.10'          # hardcoded in the tool; Tier 1 takes it from config
$exclusions = @($static, '5.6.7.8', '9.9.9.9')   # static + detected + retired-in-grace
$corpus = @(
    # plain classes
    '10.0.0.1', '172.16.5.5', '192.168.1.1', '100.64.1.1', '127.0.0.1', '169.254.1.1',
    '224.0.0.1', '0.1.2.3', '240.0.0.1', '::1', '::', 'fe80::1', 'ff02::1', 'fd00::1',
    # tunnels
    '2001:0:4136:e378::1', '64:ff9b:1::1',
    # alternate spellings
    '::ffff:10.0.0.1', '::ffff:8.8.8.8', '167772161', '0x0a000001', '3405803786', '2001:db8::1%5', 'fec0::1',
    # own set
    '203.0.113.10', '5.6.7.8', '::ffff:5.6.7.8', '9.9.9.9',
    # embedded IPv4 (NAT64 / 6to4 / SIIT / IPv4-compatible)
    '64:ff9b::a00:1', '64:ff9b::808:808', '64:ff9b::cb00:710a', '2002:c0a8:101::1',
    '2002:808:808::1', '::ffff:0:a00:1', '::ffff:0:808:808', '::ffff:0:506:708', '::7f00:1',
    # public / garbage
    '8.8.8.8', '2606:4700::1111', 'not-an-ip'
)

$root = New-TestStateRoot
try {
    $null = New-Item -ItemType Directory -Force -Path (Join-Path $root 'state')
    @{ detected = @('5.6.7.8'); last_known = @('5.6.7.8'); recorded_static = @($static)
       previous = @(@{ ip = '9.9.9.9'; retired_at = [datetime]::UtcNow.ToString('o') }) } |
        ConvertTo-Json -Depth 4 | Set-Content (Join-Path $root 'state\ownip.json')
    $env:NETWATCH_STATE = $root
    Remove-Item Env:VT_KEY, Env:ABUSEIPDB_KEY -ErrorAction SilentlyContinue   # keyless: no lookups
    try {
        $tool = Join-Path $src 'tier2\tools\check-reputation.ps1'
        foreach ($ip in $corpus) {
            $t1 = Test-ExcludedFromLookup -Ip $ip -Exclusions $exclusions
            $out = (& pwsh -NoProfile -File $tool -Ip $ip) -join "`n" | ConvertFrom-Json
            $t2 = if ($out.PSObject.Properties['refused']) { $out.refused }
                  elseif ($out.PSObject.Properties['error']) { 'invalid' }   # tool: 'not an IP literal'
                  else { $null }
            Assert-Equal "$t1" "$t2" "parity for '$ip' (tier1=[$t1] tool=[$t2])"
        }
    }
    finally { Remove-Item Env:NETWATCH_STATE -ErrorAction SilentlyContinue }
}
finally { Remove-TestStateRoot $root }

Complete-Tests
