# toast.tests.ps1 - F16 failure path. BurntToast is NOT installed on this
# machine (probe 2026-08-27), so the failure branch is the live-testable one;
# the success path is a deploy-checklist verification item.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\toast.psm1" -Force

# Precondition check: if BurntToast IS present, the failure-path assertions
# below would be meaningless - detect and report instead of asserting blindly.
$bt = Get-Module -ListAvailable BurntToast
if ($bt) {
    Write-Host 'NOTE: BurntToast is now installed; failure-path test skipped, success path exercised instead.'
}

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg

    # --- suppression gate (2026-08-27): every OTHER test file runs with
    # NETWATCH_SUPPRESS_TOAST set by _assert.ps1 - repeated suite runs were
    # spamming the operator's notification center with ALARM/CLEAN toasts.
    # PSModulePath is emptied so only the suppression gate can produce exit 0.
    $oldPSMP = $env:PSModulePath
    $env:PSModulePath = $root
    & pwsh -NoProfile -File "$PSScriptRoot\..\src\tier1\send-toast.ps1" -Title 'suppressed' -Message 'suppressed' 2>$null
    Assert-Equal 0 $LASTEXITCODE 'suppressed toast exits 0 without loading BurntToast'
    $env:PSModulePath = $oldPSMP

    # this file is the ONE intended real-pipeline exercise: lift suppression
    Remove-Item Env:NETWATCH_SUPPRESS_TOAST -ErrorAction SilentlyContinue

    $result = Send-NetwatchToast -Config $cfg -Title 'netwatch test' -Message 'toast pipeline check'
    if ($bt) {
        Assert-True $result 'toast succeeds with BurntToast installed'
    }
    else {
        Assert-False $result 'toast reports failure without BurntToast'
        $opFile = Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')
        Assert-True ((Get-Content $opFile -Raw) -match 'ERROR toast failed') 'failure logged as ERROR (F16)'
    }
    # regardless of outcome: the call returned instead of throwing
    Assert-True $true 'pipeline continued past toast'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
