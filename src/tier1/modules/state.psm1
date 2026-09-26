# state.psm1 - netwatch Tier-1 state layer: config load/validation, whitelist
# with last-good fallback (F20), op/conn logs (F21-safe), suppression cache,
# proposals (D1), retention housekeeping (D5).
# All mutable files live under cfg.paths.state_root; this module never writes
# into the code root.

Set-StrictMode -Version Latest

$script:LastGoodWhitelist = $null

function Expand-NetwatchPath {
    param([Parameter(Mandatory)] [string]$Path)
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-NetwatchConfig {
    # Loads + schema-validates config; expands env vars in path-bearing fields;
    # resolves tier2.claude_exe 'auto' via PATH. Throws on invalid config
    # (a monitor with a broken config must not start half-configured).
    param([Parameter(Mandatory)] [string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw
    $schemaFile = Join-Path $PSScriptRoot '..\..\..\schemas\config.schema.json'
    if (-not (Test-Json -Json $raw -SchemaFile $schemaFile -ErrorAction SilentlyContinue)) {
        throw "config failed schema validation: $Path"
    }
    $cfg = $raw | ConvertFrom-Json

    $cfg.paths.state_root = Expand-NetwatchPath $cfg.paths.state_root
    $cfg.paths.code_root  = Expand-NetwatchPath $cfg.paths.code_root
    if ($cfg.paths.PSObject.Properties['whitelist']) {
        $cfg.paths.whitelist = Expand-NetwatchPath $cfg.paths.whitelist
    }
    else {
        $cfg.paths | Add-Member -NotePropertyName whitelist `
            -NotePropertyValue (Join-Path $cfg.paths.state_root 'whitelist.json')
    }
    if ($cfg.PSObject.Properties['sni']) {
        $cfg.sni.tshark_exe = Expand-NetwatchPath $cfg.sni.tshark_exe
    }

    if ($cfg.tier2.claude_exe -eq 'auto') {
        $cmd = Get-Command claude -ErrorAction SilentlyContinue
        if (-not $cmd) { throw "tier2.claude_exe is 'auto' but claude is not on PATH" }
        $cfg.tier2.claude_exe = $cmd.Source
    }
    else {
        $cfg.tier2.claude_exe = Expand-NetwatchPath $cfg.tier2.claude_exe
    }
    if (-not $cfg.tier2.PSObject.Properties['claude_args_prefix']) {
        $cfg.tier2 | Add-Member -NotePropertyName claude_args_prefix -NotePropertyValue @()
    }
    return $cfg
}

function Initialize-StateRoot {
    param([Parameter(Mandatory)] $Config)
    foreach ($d in 'state', 'logs', 'escalations', 'alarms') {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $Config.paths.state_root $d)
    }
}

function Get-Whitelist {
    # Loads + validates the live whitelist; seeds it from the repo seed file on
    # first run. Invalid/corrupt file => returns last-good copy with
    # .load_error set; never returns an empty whitelist after a good load (F20).
    param([Parameter(Mandatory)] $Config)

    $wlPath = $Config.paths.whitelist
    if (-not (Test-Path -LiteralPath $wlPath)) {
        $seed = Join-Path $Config.paths.code_root 'config\whitelist.seed.json'
        Copy-Item -LiteralPath $seed -Destination $wlPath
        Write-OpLog -Config $Config -Level INFO -Message "whitelist seeded from $seed"
    }

    $schemaFile = Join-Path $PSScriptRoot '..\..\..\schemas\whitelist.schema.json'
    try {
        $raw = Get-Content -LiteralPath $wlPath -Raw
        if (-not (Test-Json -Json $raw -SchemaFile $schemaFile -ErrorAction SilentlyContinue)) {
            throw 'whitelist failed schema validation'
        }
        $wl = $raw | ConvertFrom-Json
        $script:LastGoodWhitelist = $wl
        # inert entries (no destination and not process+port) never match;
        # say so once per load instead of failing the file (schema $comment)
        foreach ($e in @($wl.entries)) {
            $m = $e.match
            $has = { param($f) [bool]($m.PSObject.Properties[$f] -and @($m.$f).Count -gt 0) }
            $dest = (& $has 'domains') -or (& $has 'domain_suffixes') -or (& $has 'cidrs')
            $pinned = (& $has 'processes') -and ((& $has 'ports') -or (& $has 'local_ports'))
            if (-not $dest -and -not $pinned) {
                Write-OpLog -Config $Config -Level WARN -Message "whitelist entry '$($e.id)' is inert (no domains/domain_suffixes/cidrs and not processes+ports) - it never matches"
            }
        }
        return $wl
    }
    catch {
        $msg = $_.Exception.Message
        Write-OpLog -Config $Config -Level ERROR -Message "whitelist load failed ($msg); keeping last-good copy"
        if ($null -eq $script:LastGoodWhitelist) {
            throw "whitelist invalid and no last-good copy exists: $msg"
        }
        $bad = $script:LastGoodWhitelist | ConvertTo-Json -Depth 10 | ConvertFrom-Json  # detached copy
        $bad | Add-Member -NotePropertyName load_error -NotePropertyValue $msg -Force
        return $bad
    }
}

function Write-OpLog {
    # Operational log; write failures degrade to stderr, never throw (F21).
    # Filename date comes from the SAME UTC clock as the line timestamp - a
    # local-date filename put post-midnight-UTC lines in the previous day's
    # file on this UTC-7 machine. $NowUtc is a test seam.
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [ValidateSet('TRACE', 'INFO', 'WARN', 'ERROR')] [string]$Level,
        [Parameter(Mandatory)] [string]$Message,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $line = '{0} {1} {2}' -f $NowUtc.ToString('o'), $Level, $Message
    try {
        $file = Join-Path $Config.paths.state_root ('logs\netwatch-' + $NowUtc.ToString('yyyyMMdd') + '.log')
        Add-Content -LiteralPath $file -Value $line -Encoding utf8
    }
    catch {
        [Console]::Error.WriteLine("oplog write failed: $line")
    }
}

function Write-ConnLog {
    # One jsonl line per classified connection; failures logged, never thrown.
    # Filename date in UTC for the same reason as Write-OpLog.
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] $Record,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    try {
        $file = Join-Path $Config.paths.state_root ('logs\conn-' + $NowUtc.ToString('yyyyMMdd') + '.jsonl')
        Add-Content -LiteralPath $file -Value (($Record | ConvertTo-Json -Depth 10 -Compress)) -Encoding utf8
    }
    catch {
        Write-OpLog -Config $Config -Level ERROR -Message "conn log write failed: $($_.Exception.Message)"
    }
}

function Get-SuppressionTable {
    # Internal: loads suppression.json pruning expired entries.
    param([Parameter(Mandatory)] $Config)
    $file = Join-Path $Config.paths.state_root 'state\suppression.json'
    $table = @{}
    if (Test-Path -LiteralPath $file) {
        try {
            $obj = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -AsHashtable
            $now = [datetime]::UtcNow
            foreach ($k in $obj.Keys) {
                # per-entry guard (reviewer 2026-08-28): one corrupt entry
                # must drop ONLY itself, not whichever siblings the hashtable
                # happened to order after it
                try {
                    if ([datetime]::Parse($obj[$k].expires_utc).ToUniversalTime() -gt $now) {
                        $table[$k] = $obj[$k]
                    }
                }
                catch {
                    Write-OpLog -Config $Config -Level WARN -Message "suppression entry '$k' corrupt, dropped: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-OpLog -Config $Config -Level ERROR -Message "suppression cache unreadable, starting empty: $($_.Exception.Message)"
        }
    }
    return $table
}

function Add-Suppression {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [int]$TtlHours
    )
    $table = Get-SuppressionTable -Config $Config
    $now = [datetime]::UtcNow
    $table[$Key] = @{
        added_utc   = $now.ToString('o')
        expires_utc = $now.AddHours($TtlHours).ToString('o')
    }
    $file = Join-Path $Config.paths.state_root 'state\suppression.json'
    $table | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding utf8
}

function Test-Suppressed {
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$Key
    )
    return (Get-SuppressionTable -Config $Config).ContainsKey($Key)
}

function Add-Proposal {
    # Appends a Tier-2 whitelist proposal (D1: proposals only, never applied).
    # A second proposal for the same key is marked double_clean.
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] $Proposal,
        [Parameter(Mandatory)] [string]$PacketId
    )
    $file = Join-Path $Config.paths.state_root 'state\proposals.jsonl'
    $isRepeat = $false
    if (Test-Path -LiteralPath $file) {
        foreach ($line in Get-Content -LiteralPath $file) {
            try { if (($line | ConvertFrom-Json).key -eq $Key) { $isRepeat = $true; break } } catch {}
        }
    }
    $record = [ordered]@{
        ts_utc       = [datetime]::UtcNow.ToString('o')
        key          = $Key
        packet_id    = $PacketId
        double_clean = $isRepeat
        proposal     = $Proposal
    }
    Add-Content -LiteralPath $file -Value ($record | ConvertTo-Json -Depth 10 -Compress) -Encoding utf8
}

function Invoke-Housekeeping {
    # D5 retention + quota ledger daily reset. Failures logged, never fatal.
    param([Parameter(Mandatory)] $Config)
    $root = $Config.paths.state_root
    $r = $Config.retention_days
    $plans = @(
        @{ dir = 'logs';        filter = 'conn-*.jsonl';     days = $r.conn_logs }
        @{ dir = 'logs';        filter = 'netwatch-*.log';   days = $r.op_logs }
        @{ dir = 'escalations'; filter = '*';                days = $r.escalations }
        @{ dir = 'alarms';      filter = '*';                days = $r.alarms }
    )
    foreach ($p in $plans) {
        try {
            $cutoff = (Get-Date).AddDays(-$p.days)
            Get-ChildItem -Path (Join-Path $root $p.dir) -Filter $p.filter -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force
                    Write-OpLog -Config $Config -Level INFO -Message "retention: removed $($_.Name)"
                }
        }
        catch {
            Write-OpLog -Config $Config -Level ERROR -Message "housekeeping failed for $($p.dir): $($_.Exception.Message)"
        }
    }
    # quota ledger: reset counters when the date rolled over. Taken under the
    # SAME named mutex check-reputation.ps1 uses (name = hash of the ledger
    # path) - an unlocked read-then-overwrite here could wipe a reservation a
    # concurrent Tier-2 call just wrote (review finding). Busy -> skip: the
    # tool resets a stale date itself on its next read, nothing is lost.
    $ledgerFile = Join-Path $root 'state\repquota.json'
    $mutex = [System.Threading.Mutex]::new($false, (Get-LedgerMutexName -LedgerFile $ledgerFile))
    $held = $false
    try {
        try { $held = $mutex.WaitOne(2000) }
        catch [System.Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) {
            Write-OpLog -Config $Config -Level WARN -Message 'quota ledger busy - daily reset skipped (tool resets on its next read)'
            return
        }
        $today = Get-Date -Format 'yyyy-MM-dd'
        $fresh = @{ date = $today; vt_today = 0; vt_minute = @(); abuse_today = 0 }
        $write = $null
        if (-not (Test-Path -LiteralPath $ledgerFile)) { $write = $fresh }
        else {
            $ledger = $null
            try { $ledger = Get-Content -LiteralPath $ledgerFile -Raw | ConvertFrom-Json } catch {}
            # same required fields the tool checks (Read-Ledger); a parseable
            # ledger missing a counter is refused there too and would stay
            # unusable until the next date roll
            $malformed = $null -eq $ledger
            if (-not $malformed) {
                foreach ($f in 'date', 'vt_today', 'abuse_today') {
                    if (-not $ledger.PSObject.Properties[$f]) { $malformed = $true }
                }
            }
            if ($malformed) {
                # torn/foreign ledger (the tool refuses lookups on it): repair it
                # AS EXHAUSTED for today - re-zeroing mid-day could over-spend the
                # free-tier budget; tomorrow's reset starts clean
                $q = $Config.reputation_quota
                $write = @{ date = $today; vt_today = $q.vt_per_day; vt_minute = @(); abuse_today = $q.abuseipdb_per_day }
                Write-OpLog -Config $Config -Level WARN -Message 'quota ledger unreadable - rewritten as exhausted for today'
            }
            elseif ($ledger.date -ne $today) { $write = $fresh }
        }
        if ($null -ne $write) {
            $tmp = "$ledgerFile.$PID.tmp"                       # atomic, like the tool
            $write | ConvertTo-Json | Set-Content -LiteralPath $tmp -Encoding utf8
            [IO.File]::Move($tmp, $ledgerFile, $true)
            if ($write -eq $fresh) { Write-OpLog -Config $Config -Level INFO -Message 'quota ledger reset' }
        }
    }
    catch {
        Write-OpLog -Config $Config -Level ERROR -Message "quota ledger reset failed: $($_.Exception.Message)"
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Get-LedgerMutexName {
    # MUST stay identical to the derivation in src/tier2/tools/check-reputation.ps1
    # (duplicated there on purpose: that file stays import-free; drift is
    # caught by tests/duplication-sync.tests.ps1).
    param([Parameter(Mandatory)] [string]$LedgerFile)
    return 'netwatch-repquota-' + [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($LedgerFile.ToLowerInvariant()))).Substring(0, 16)
}

Export-ModuleMember -Function Get-NetwatchConfig, Initialize-StateRoot, Get-Whitelist,
    Write-OpLog, Write-ConnLog, Add-Suppression, Test-Suppressed, Add-Proposal,
    Invoke-Housekeeping, Expand-NetwatchPath, Get-LedgerMutexName
