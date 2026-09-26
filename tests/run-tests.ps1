# run-tests.ps1 - netwatch test harness. Runs every tests/*.tests.ps1 in its
# own pwsh child process (isolation: module state, strict mode, trap).
# Usage: pwsh -NoProfile -File tests/run-tests.ps1 [-Filter <wildcard>]
# Exit 0 = all green; 1 = any failure.

#Requires -Version 7.6
param([string]$Filter = '*')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$files = @(Get-ChildItem -Path $PSScriptRoot -Filter "$Filter.tests.ps1" | Sort-Object Name)
if (-not $files) { Write-Host "no test files match '$Filter'"; exit 1 }

$failed = @()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($f in $files) {
    Write-Host "=== $($f.Name) ===" -ForegroundColor Cyan
    & pwsh -NoProfile -File $f.FullName
    if ($LASTEXITCODE -ne 0) { $failed += $f.Name }
}
$sw.Stop()

Write-Host ''
if ($failed) {
    Write-Host ("FAILED ({0}/{1}): {2}" -f $failed.Count, $files.Count, ($failed -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host ("ALL PASS ({0} files, {1:n1}s)" -f $files.Count, $sw.Elapsed.TotalSeconds) -ForegroundColor Green
exit 0
