# state.tests.ps1 - config load, whitelist seed/last-good, logs, suppression,
# proposals, housekeeping.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force

$root = New-TestStateRoot
try {
    # --- config load ---------------------------------------------------------
    $cfgPath = New-TestConfig -StateRoot $root
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Assert-Equal $root $cfg.paths.state_root 'state_root passthrough'
    Assert-True (Test-Path $cfg.tier2.claude_exe) "claude 'auto' resolved to a real file: $($cfg.tier2.claude_exe)"
    Assert-True ($cfg.tier2.claude_exe -like '*claude*') 'resolved exe is claude'
    Assert-Equal 30 $cfg.sample_interval_sec 'interval loaded'

    # env-var expansion in paths: rewrite the state_root in percent-form
    $base = [Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%\netwatch')
    $percentRoot = $root.Replace($base, '%LOCALAPPDATA%\netwatch')
    Assert-True ($percentRoot.Contains('%')) 'precondition: percent-form built'
    $cfgPath2 = New-TestConfig -StateRoot $root -Override @{
        paths = @{ state_root = $percentRoot }
    }
    $cfg2 = Get-NetwatchConfig -Path $cfgPath2
    Assert-Equal $root $cfg2.paths.state_root 'percent vars expanded to real path'

    # schema-invalid config throws (unknown top-level key)
    $badPath = New-TestConfig -StateRoot $root -Override @{ bogus_key = 1 }
    Assert-Throws { Get-NetwatchConfig -Path $badPath } 'unknown key rejected by schema'

    # --- state root init -----------------------------------------------------
    Initialize-StateRoot -Config $cfg
    foreach ($d in 'state', 'logs', 'escalations', 'alarms') {
        Assert-True (Test-Path (Join-Path $root $d)) "subdir $d created"
    }

    # --- whitelist: seed on first load --------------------------------------
    $wl = Get-Whitelist -Config $cfg
    Assert-True (Test-Path $cfg.paths.whitelist) 'whitelist seeded into state root'
    Assert-True ($wl.entries.Count -ge 5) 'seed entries loaded'
    Assert-Null ($wl.PSObject.Properties['load_error']?.Value) 'no load_error on good load'

    # --- whitelist: corrupt file keeps last-good (F20) -----------------------
    Set-Content -LiteralPath $cfg.paths.whitelist -Value '{ not json !!!'
    $wl2 = Get-Whitelist -Config $cfg
    Assert-True ($wl2.entries.Count -ge 5) 'last-good entries survive corrupt file'
    Assert-NotNull $wl2.load_error 'load_error reported'

    # schema-invalid (parses, wrong shape) also keeps last-good
    '{"version":1,"entries":[{"id":"x"}]}' | Set-Content -LiteralPath $cfg.paths.whitelist
    $wl3 = Get-Whitelist -Config $cfg
    Assert-True ($wl3.entries.Count -ge 5) 'last-good survives schema-invalid file'
    Assert-NotNull $wl3.load_error 'load_error on schema-invalid'

    # --- op log --------------------------------------------------------------
    Write-OpLog -Config $cfg -Level INFO -Message 'hello op log'
    $opFile = Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')
    Assert-True (Test-Path $opFile) 'op log file created'
    Assert-True ((Get-Content $opFile -Raw) -match 'INFO hello op log') 'op log line format'

    # --- conn log ------------------------------------------------------------
    Write-ConnLog -Config $cfg -Record @{ key = 'proc|example.com|443'; verdict = 'whitelisted' }
    $connFile = Join-Path $root ('logs\conn-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.jsonl')
    $line = (Get-Content $connFile | Select-Object -First 1) | ConvertFrom-Json
    Assert-Equal 'proc|example.com|443' $line.key 'conn log jsonl round-trip'

    # --- log filenames follow the LINE timezone (UTC), not the local date ----
    # Machine is UTC-7: between 00:00Z and 07:00Z lines dated day N+1 landed
    # in the file named day N. Filename must derive from the same UTC clock
    # as the line content.
    $rollNow = [datetime]::new(2027, 1, 2, 3, 0, 0, [DateTimeKind]::Utc)   # local: 2027-01-01 20:00
    Write-OpLog -Config $cfg -Level INFO -Message 'utc filename check' -NowUtc $rollNow
    Assert-True (Test-Path (Join-Path $root 'logs\netwatch-20270102.log')) 'op log filename uses UTC date'
    Write-ConnLog -Config $cfg -Record @{ key = 'k|1.2.3.4|443' } -NowUtc $rollNow
    Assert-True (Test-Path (Join-Path $root 'logs\conn-20270102.jsonl')) 'conn log filename uses UTC date'

    # --- suppression ---------------------------------------------------------
    Assert-False (Test-Suppressed -Config $cfg -Key 'k1') 'k1 not suppressed initially'
    Add-Suppression -Config $cfg -Key 'k1' -TtlHours 24
    Assert-True (Test-Suppressed -Config $cfg -Key 'k1') 'k1 suppressed after add'
    # expired entry pruned on load: write file directly with past expiry
    $supFile = Join-Path $root 'state\suppression.json'
    '{"kOld":{"expires_utc":"2020-01-01T00:00:00Z","added_utc":"2020-01-01T00:00:00Z"}}' |
        Set-Content -LiteralPath $supFile
    Assert-False (Test-Suppressed -Config $cfg -Key 'kOld') 'expired entry not suppressed'

    # ONE corrupt entry must not wipe the whole table (reviewer NOTE,
    # 2026-08-28: the loop-level catch returned an empty table)
    ('{"kGood":{"expires_utc":"2099-01-01T00:00:00Z","added_utc":"2020-01-01T00:00:00Z"},' +
     '"kBad":{"expires_utc":"not-a-date","added_utc":"x"}}') |
        Set-Content -LiteralPath $supFile
    Assert-True (Test-Suppressed -Config $cfg -Key 'kGood') 'good entry survives a corrupt sibling'
    Assert-False (Test-Suppressed -Config $cfg -Key 'kBad') 'corrupt entry itself dropped'

    # --- proposals -----------------------------------------------------------
    $prop = @{ id = 'test-prop'; match = @{ domains = @('example.com') }
               added_by = 'tier3'; added_at = '2026-08-27T00:00:00Z'; evidence = 'test' }
    Add-Proposal -Config $cfg -Key 'k1' -Proposal $prop -PacketId 'p1'
    Add-Proposal -Config $cfg -Key 'k1' -Proposal $prop -PacketId 'p2'
    $lines = @(Get-Content (Join-Path $root 'state\proposals.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-Equal 2 $lines.Count 'two proposal lines'
    Assert-False ([bool]$lines[0].double_clean) 'first proposal not double_clean'
    Assert-True  ([bool]$lines[1].double_clean) 'second same-key proposal marked double_clean (D1)'

    # --- housekeeping / retention (D5) --------------------------------------
    $oldConn = Join-Path $root 'logs\conn-20250101.jsonl'
    'x' | Set-Content -LiteralPath $oldConn
    (Get-Item $oldConn).LastWriteTime = (Get-Date).AddDays(-30)
    $oldEsc = Join-Path $root 'escalations\20250101-000000-packet.json'
    'x' | Set-Content -LiteralPath $oldEsc
    (Get-Item $oldEsc).LastWriteTime = (Get-Date).AddDays(-100)
    $freshEsc = Join-Path $root 'escalations\fresh-packet.json'
    'x' | Set-Content -LiteralPath $freshEsc
    $oldAlarm = Join-Path $root 'alarms\20250101-alarm.json'
    'x' | Set-Content -LiteralPath $oldAlarm
    (Get-Item $oldAlarm).LastWriteTime = (Get-Date).AddDays(-100)   # < 365 d: must stay
    Invoke-Housekeeping -Config $cfg
    Assert-False (Test-Path $oldConn)  'old conn log deleted (14 d)'
    Assert-True  (Test-Path $connFile) 'today conn log kept'
    Assert-False (Test-Path $oldEsc)   'old escalation deleted (90 d)'
    Assert-True  (Test-Path $freshEsc) 'fresh escalation kept'
    Assert-True  (Test-Path $oldAlarm) 'alarm kept (365 d)'
    # quota ledger reset on date change
    $ledger = Join-Path $root 'state\repquota.json'
    '{"date":"2020-01-01","vt_today":399,"vt_minute":[],"abuse_today":5}' | Set-Content -LiteralPath $ledger
    Invoke-Housekeeping -Config $cfg
    $q = Get-Content $ledger -Raw | ConvertFrom-Json
    Assert-Equal (Get-Date -Format 'yyyy-MM-dd') $q.date 'ledger date reset'
    Assert-Equal 0 $q.vt_today 'vt counter reset'

    # reset runs under the ledger mutex check-reputation uses: while it is
    # held, housekeeping must NOT overwrite the ledger (review finding)
    $expectName = 'netwatch-repquota-' + [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($ledger.ToLowerInvariant()))).Substring(0, 16)
    Assert-Equal $expectName (Get-LedgerMutexName -LedgerFile $ledger) 'mutex name matches the tool derivation'
    # tool-side derivation parity: tests/duplication-sync.tests.ps1 (AST)
    '{"date":"2020-01-01","vt_today":7,"vt_minute":[],"abuse_today":5}' | Set-Content -LiteralPath $ledger
    # held from ANOTHER process (a mutex is re-entrant for its own thread)
    $holder = Start-Process pwsh -PassThru -NoNewWindow -ArgumentList '-NoProfile', '-File',
        (Join-Path $PSScriptRoot 'stubs\hold-mutex.ps1'), '-Name', $expectName, '-Seconds', '6'
    Start-Sleep -Seconds 3
    Invoke-Housekeeping -Config $cfg
    $q = Get-Content $ledger -Raw | ConvertFrom-Json
    Assert-Equal 7 $q.vt_today 'held ledger mutex -> housekeeping leaves the ledger alone'
    $holder.WaitForExit()
    Invoke-Housekeeping -Config $cfg
    $q = Get-Content $ledger -Raw | ConvertFrom-Json
    Assert-Equal 0 $q.vt_today 'free mutex -> reset happens'
    Assert-Equal 0 @(Get-ChildItem (Split-Path $ledger) -Filter '*.tmp').Count 'atomic write leaves no temp file'

    # a torn ledger is repaired AS EXHAUSTED for today, never re-zeroed
    '{"date":"20' | Set-Content -LiteralPath $ledger
    Invoke-Housekeeping -Config $cfg
    $q = Get-Content $ledger -Raw | ConvertFrom-Json
    Assert-Equal (Get-Date -Format 'yyyy-MM-dd') $q.date 'repaired ledger dated today'
    Assert-Equal $cfg.reputation_quota.vt_per_day $q.vt_today 'repaired ledger: vt exhausted for today'
    Assert-Equal $cfg.reputation_quota.abuseipdb_per_day $q.abuse_today 'repaired ledger: abuse exhausted for today'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
