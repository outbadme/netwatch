# probe.tests.ps1 - install/probe-environment.ps1: report shape, -Strict exit
# code, -AllowMissing. Runs the probe as a child with a PATH that holds only
# pwsh, so node / claude / npm are missing on every machine.
. "$PSScriptRoot\_assert.ps1"

$probe = Join-Path $PSScriptRoot '..\install\probe-environment.ps1'
$pwshExe = (Get-Process -Id $PID).Path
$savedPath = $env:PATH
function Invoke-Probe([string[]]$ProbeArgs) {
    $out = & $pwshExe -NoProfile -File $probe @ProbeArgs 2>$null
    $json = ($out | Where-Object { $_ -notmatch '^probe:' }) -join "`n"
    return @{ rc = $LASTEXITCODE; report = ($json | ConvertFrom-Json) }
}
try {
    $env:PATH = Split-Path -Parent $pwshExe
    $r = Invoke-Probe @()
    Assert-Equal 0 $r.rc 'report-only mode exits 0 even with gaps'
    Assert-True (@($r.report.below_minimum) -contains 'node: missing (min 24.0)') 'missing node reported'
    Assert-True ($r.report.PSObject.Properties.Name -contains 'mcp_deps') 'mcp deps reported'
    Assert-True ($r.report.PSObject.Properties.Name -contains 'sysmon_version') 'sysmon version reported'
    Assert-False (@($r.report.below_minimum) -match '^sysmon') 'absent Sysmon is not a gap (optional)'

    $r = Invoke-Probe @('-Strict')
    Assert-Equal 1 $r.rc '-Strict with gaps exits 1'

    $r = Invoke-Probe @('-Strict', '-AllowMissing', 'node,claude,burnttoast,mcp_deps')
    Assert-Equal 0 $r.rc '-AllowMissing tolerates absent components'
    Assert-Equal 0 @($r.report.below_minimum).Count 'nothing left below minimum'
}
finally { $env:PATH = $savedPath }
Complete-Tests
