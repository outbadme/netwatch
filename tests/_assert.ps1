# _assert.ps1 - minimal assertion helpers for netwatch tests (no Pester:
# module installs are machine changes and are operator-gated).
# Dot-source at the top of every *.tests.ps1:
#   . "$PSScriptRoot\_assert.ps1"
# Each test file runs in its own pwsh process (see run-tests.ps1); any throw
# is caught by the trap below and turns into exit 1.
# Jail note: the state root is always referenced via the %LOCALAPPDATA%
# percent-form expanded at runtime - the only form the guard accepts.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AssertCount = 0
$script:NetwatchStateBase = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch')

# Tests must not spam the operator's notification center (2026-08-27: suite
# reruns produced a stream of real ALARM/CLEAN toasts). send-toast.ps1 honors
# this and exits 0 without showing anything; child processes (netwatch.ps1,
# launch-tier3.ps1) inherit it. toast.tests.ps1 lifts it for the one
# intended real-pipeline check.
$env:NETWATCH_SUPPRESS_TOAST = '1'

trap {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 1
}

function Assert-True {
    param(
        [Parameter(Mandatory)] [AllowNull()] $Condition,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    if (-not $Condition) { throw "Assert-True failed: $Message" }
}

function Assert-False {
    param(
        [Parameter(Mandatory)] [AllowNull()] $Condition,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    if ($Condition) { throw "Assert-False failed: $Message" }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)] [AllowNull()] $Expected,
        [Parameter(Mandatory)] [AllowNull()] $Actual,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    if ("$Expected" -cne "$Actual") {
        throw "Assert-Equal failed: $Message (expected [$Expected], got [$Actual])"
    }
}

function Assert-Null {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    if ($null -ne $Value) { throw "Assert-Null failed: $Message (got [$Value])" }
}

function Assert-NotNull {
    param(
        [AllowNull()] $Value,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    if ($null -eq $Value) { throw "Assert-NotNull failed: $Message" }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)] [scriptblock]$Script,
        [Parameter(Mandatory)] [string]$Message
    )
    $script:AssertCount++
    $threw = $false
    try { & $Script } catch { $threw = $true }
    if (-not $threw) { throw "Assert-Throws failed (no exception): $Message" }
}

function New-TestStateRoot {
    # Throwaway state root INSIDE the allowed jail root (state base above).
    $name = 'test-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $path = Join-Path $script:NetwatchStateBase $name
    $null = New-Item -ItemType Directory -Path $path -Force
    return $path
}

function Remove-TestStateRoot {
    param([Parameter(Mandatory)] [string]$Path)
    # Refuse to delete anything that is not a test-* dir under the state root.
    if ($Path -notlike (Join-Path $script:NetwatchStateBase 'test-*')) {
        throw "Remove-TestStateRoot refuses non-test path: $Path"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

$script:SkipCount = 0

function Skip-Test {
    # A case that cannot run on this machine (missing privilege, feature
    # disabled, deps not installed). Counted and reported, never silent:
    # run-tests.ps1 lists every skip, and with NETWATCH_REQUIRE_ALL=1 (CI) a
    # skip is a failure - a security test that did not run has not passed.
    param([Parameter(Mandatory)] [string]$Reason)
    $script:SkipCount++
    $file = Split-Path -Leaf ($MyInvocation.PSCommandPath ?? $PSCommandPath)
    if ($env:NETWATCH_REQUIRE_ALL -eq '1') { throw "required case skipped: $Reason" }
    Write-Host "SKIP: $Reason" -ForegroundColor Yellow
    if ($env:NETWATCH_SKIP_LOG) {
        try { Add-Content -LiteralPath $env:NETWATCH_SKIP_LOG -Value "${file}: $Reason" -Encoding utf8 } catch {}
    }
}

function Complete-Tests {
    # Call as the last line of a test file.
    $sk = if ($script:SkipCount) { ", $($script:SkipCount) skipped" } else { '' }
    Write-Host "OK: $script:AssertCount assertions passed$sk" -ForegroundColor Green
    exit 0
}
