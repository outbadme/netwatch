# sleeper.ps1 - records its own PID then sleeps; used to prove Kill($true)
# takes down the whole Tier-2 process tree (F1).
param([Parameter(Mandatory)] [string]$PidFile)
Set-Content -LiteralPath $PidFile -Value $PID
Start-Sleep -Seconds 120
