# hold-mutex.ps1 - test stub: owns a named mutex for -Seconds, then releases.
# A mutex is re-entrant for its owning thread, so contention tests need the
# holder in ANOTHER process.
param(
    [Parameter(Mandatory)] [string]$Name,
    [int]$Seconds = 6
)
$m = [System.Threading.Mutex]::new($true, $Name)
Start-Sleep -Seconds $Seconds
$m.ReleaseMutex()
$m.Dispose()
