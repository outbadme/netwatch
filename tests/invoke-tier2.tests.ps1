# invoke-tier2.tests.ps1 - capped Tier-2 launcher against stub-claude.cmd:
# clean/alarm envelopes, garbage output, F24 key drop, F1 tree-kill timeout,
# launch failure.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"

$invoke = Resolve-Path "$PSScriptRoot\..\src\tier1\invoke-tier2.ps1"
$stub   = Resolve-Path "$PSScriptRoot\stubs\stub-claude.cmd"

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = "$stub"; wall_clock_cap_sec = 5 }
    }
    foreach ($d in 'state', 'escalations', 'logs') {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $root $d)
    }

    # minimal schema-shaped packet with two keys
    $packet = [ordered]@{
        packet_id        = '20260827-000001'
        created_utc      = [datetime]::UtcNow.ToString('o')
        collector_health = @{ sni_capture = 'unavailable'; dns_etw = 'unavailable' }
        machine_notes    = @('test note')
        connections      = @(
            [ordered]@{
                key = 'proca|1.2.3.4|443'
                process = @{ pid = 111; name = 'proca' }
                remote = @{ ip = '1.2.3.4'; port = 443 }
                direction = 'outbound'
                first_seen_utc = [datetime]::UtcNow.ToString('o')
                samples_seen = 2
                attribution = @{ source = 'none' }
            }
            [ordered]@{
                key = 'procb|evil.example|8443'
                process = @{ pid = 222; name = 'procb' }
                remote = @{ ip = '5.6.7.8'; port = 8443 }
                direction = 'outbound'
                first_seen_utc = [datetime]::UtcNow.ToString('o')
                samples_seen = 3
                attribution = @{ source = 'dns-pid'; domain = 'evil.example' }
            }
        )
    }
    $packetPath = Join-Path $root 'escalations\20260827-000001-packet.json'
    $packet | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $packetPath

    function Invoke-Launcher {
        param([string]$Mode)
        $env:STUB_MODE = $Mode
        try {
            & pwsh -NoProfile -File $invoke -PacketPath $packetPath -ConfigPath $cfgPath | Out-Null
            return $LASTEXITCODE
        }
        finally { Remove-Item Env:STUB_MODE -ErrorAction SilentlyContinue }
    }

    # --- clean ---------------------------------------------------------------
    $rc = Invoke-Launcher 'clean'
    Assert-Equal 0 $rc 'clean run exit 0'
    $verdictFile = Join-Path $root 'escalations\20260827-000001-verdict.json'
    Assert-True (Test-Path $verdictFile) 'verdict file written'
    $v = Get-Content $verdictFile -Raw | ConvertFrom-Json
    Assert-Equal 'stub-session-123' $v.session_id 'session id captured for tier3'
    Assert-Equal 'CLEAN' $v.verdict.verdict 'verdict CLEAN'
    Assert-Equal 2 $v.verdict.connections.Count 'both keys answered'
    Assert-NotNull $v.verdict.connections[0].proposed_whitelist_entry 'valid proposal preserved'
    Assert-True (Test-Path (Join-Path $root 'escalations\20260827-000001-stdout.json')) 'raw stdout kept (audit)'

    # --- argv: prompt by path, command line far below cmd.exe's 8191 limit ---
    # (first Windows CI run 2026-09-26: the inline prompt pushed the line to
    # ~8.1K chars and the .cmd stub died before reading stdin)
    $argsFile = [IO.Path]::GetFullPath((Join-Path $root 'stub-args.txt'))   # stub runs in another cwd
    $env:STUB_ARGS_FILE = $argsFile
    try { $rc = Invoke-Launcher 'clean' } finally { Remove-Item Env:STUB_ARGS_FILE -ErrorAction SilentlyContinue }
    Assert-Equal 0 $rc 'clean run with argv recording exit 0'
    $argv = @(Get-Content -LiteralPath $argsFile)
    $i = [array]::IndexOf($argv, '--system-prompt-file')
    Assert-True ($i -ge 0) 'launcher passes --system-prompt-file'
    Assert-True ($argv[$i + 1] -like '*system-prompt.md') 'prompt passed by path'
    Assert-False ($argv -contains '--system-prompt') 'no inline --system-prompt'
    $cmdLen = ($argv -join ' ').Length
    Assert-True ($cmdLen -lt 2000) "argv stays short ($cmdLen chars; cmd.exe limit 8191)"

    # --- session-limit envelope with exit 0 -> quota (6), not invalid output (4)
    $rc = Invoke-Launcher 'quota0'
    Assert-Equal 6 $rc '429 envelope with exit 0 classified as quota exhausted'

    # --- alarm ---------------------------------------------------------------
    $rc = Invoke-Launcher 'alarm'
    Assert-Equal 0 $rc 'alarm run exit 0 (valid verdict)'
    $v = Get-Content $verdictFile -Raw | ConvertFrom-Json
    Assert-Equal 'ALARM' $v.verdict.verdict 'verdict ALARM'

    # --- garbage output (F2) -------------------------------------------------
    $rc = Invoke-Launcher 'garbage'
    Assert-Equal 4 $rc 'garbage output exit 4'
    $op = Get-Content (Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')) -Raw
    Assert-True ($op -match 'tier2 output unparsable') 'unparsable output logged with snippet (cost diagnosis)'

    # --- schema-invalid proposal dropped, verdict stays usable (live 17:55:33Z
    # 2026-08-27: first real proposal was shape-invalid and correctly dropped;
    # this path had no regression test) ---------------------------------------
    $rc = Invoke-Launcher 'badproposal'
    Assert-Equal 0 $rc 'bad proposal does not fail the run'
    $v = Get-Content (Join-Path $root 'escalations\20260827-000001-verdict.json') -Raw | ConvertFrom-Json
    Assert-Equal 'CLEAN' $v.verdict.verdict 'verdict survives proposal drop'
    Assert-Null $v.verdict.connections[0].PSObject.Properties['proposed_whitelist_entry'] 'invalid proposal removed'
    $op = Get-Content (Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')) -Raw
    Assert-True ($op -match 'dropping schema-invalid proposal') 'proposal drop logged'

    # --- dropped key (F24) ---------------------------------------------------
    $rc = Invoke-Launcher 'dropkey'
    Assert-Equal 4 $rc 'dropped packet key exit 4 (F24)'
    $op = Get-Content (Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')) -Raw
    Assert-True ($op -match 'packet key not answered') 'F24 violation logged'

    # --- crash (started but died, no output) ---------------------------------
    $rc = Invoke-Launcher 'crash'
    Assert-Equal 4 $rc 'crash-after-start exit 4 (retry path)'

    # --- valid output but nonzero exit (F2: nonzero exit = failed run) -------
    $rc = Invoke-Launcher 'cleanfail'
    Assert-Equal 4 $rc 'valid stdout with nonzero exit still exit 4'

    # --- markdown-fenced verdict (live finding 2026-08-27): unwrapped, not
    # rejected - content still passes full shape validation afterwards -------
    $rc = Invoke-Launcher 'fenced'
    Assert-Equal 0 $rc 'fenced verdict accepted after unwrap'
    $v = Get-Content $verdictFile -Raw | ConvertFrom-Json
    Assert-Equal 'CLEAN' $v.verdict.verdict 'fenced verdict parsed to CLEAN'
    Assert-Equal 2 $v.verdict.connections.Count 'fenced verdict keys intact'

    # --- timeout + tree kill (F1) --------------------------------------------
    $pidFile = Join-Path $root 'sleeper.pid'
    $env:STUB_CHILD_PIDFILE = $pidFile
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $rc = Invoke-Launcher 'hang'
        $sw.Stop()
        Assert-Equal 2 $rc 'timeout exit 2'
        Assert-True ($sw.Elapsed.TotalSeconds -lt 20) "cap enforced (took $([int]$sw.Elapsed.TotalSeconds)s at 5s cap)"
        Assert-True (Test-Path $pidFile) 'sleeper child recorded its pid'
        # Live 2026-08-27: timeout runs 183643-203/192012-394 left NOTHING but
        # stderr - whatever partial output the model produced was discarded.
        Assert-True (Test-Path (Join-Path $root 'escalations\20260827-000001-stdout-partial.json')) 'partial stdout salvaged on timeout'
        Start-Sleep -Milliseconds 500   # let the kill settle
        $childPid = [int](Get-Content $pidFile)
        $alive = Get-Process -Id $childPid -ErrorAction SilentlyContinue
        if ($alive) { Stop-Process -Id $childPid -Force }   # cleanup before asserting
        Assert-Null $alive 'grandchild process killed by Kill(true) tree termination (F1)'
    }
    finally { Remove-Item Env:STUB_CHILD_PIDFILE -ErrorAction SilentlyContinue }

    # --- key presence is logged by NAME only (live 2026-08-27: 4 runs answered
    # reputation with vt no_key while abuseipdb worked - the op-log gave no way
    # to see that the VT key was simply never provisioned) --------------------
    $fakeKeys = [Text.Encoding]::UTF8.GetBytes('{"abuseipdb":"test-abuse-key","vt":null}')
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $fakeKeys, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes((Join-Path $root 'state\apikeys.dat'), $enc)
    $rc = Invoke-Launcher 'clean'
    Assert-Equal 0 $rc 'clean run with key file exit 0'
    $op = Get-Content (Join-Path $root ('logs\netwatch-' + ([datetime]::UtcNow.ToString('yyyyMMdd')) + '.log')) -Raw
    Assert-True ($op -match 'apikeys loaded: abuseipdb=True vt=False') 'key presence logged by name'
    Assert-False ($op -match 'test-abuse-key') 'key VALUE never logged'
    Remove-Item (Join-Path $root 'state\apikeys.dat')

    # --- prompt copies stay in sync (drift found 2026-08-27: 3820afd updated
    # prompts/ but not src/tier2/, and the launcher loads src/tier2/) ---------
    # whole file, header included: skipping line 1 hid a stale header that
    # still described the inline --system-prompt form (review 2026-09-26)
    $designPrompt  = @(Get-Content "$PSScriptRoot\..\prompts\tier2-system-prompt.md")
    $runtimePrompt = @(Get-Content "$PSScriptRoot\..\src\tier2\system-prompt.md")
    Assert-Equal ($designPrompt -join "`n") ($runtimePrompt -join "`n") 'design and runtime system prompts identical'
    Assert-True ($runtimePrompt[0] -match '--system-prompt-file') 'prompt header names the flag the launcher actually uses'

    # --- timeout salvage (D9): the kill may land AFTER the analysis finished.
    # Live 20260828-103245-317: 182s vs 180s cap, salvaged stdout held a full
    # valid 6-key CLEAN verdict - and it was discarded, raising tier3 on all 6.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rc = Invoke-Launcher 'hangafter'
    $sw.Stop()
    Assert-Equal 0 $rc 'complete salvaged verdict accepted as a normal run'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 20) 'cap still enforced on hangafter'
    $v = Get-Content (Join-Path $root 'escalations\20260827-000001-verdict.json') -Raw | ConvertFrom-Json
    Assert-Equal 'CLEAN' $v.verdict.verdict 'salvaged full verdict written'
    Assert-Equal 2 $v.verdict.connections.Count 'all keys covered in salvaged verdict'

    # partial coverage: only validated connections accepted, the rest stay F1
    $rc = Invoke-Launcher 'hangpartial'
    Assert-Equal 5 $rc 'partially salvaged verdict exits 5'
    $v = Get-Content (Join-Path $root 'escalations\20260827-000001-verdict.json') -Raw | ConvertFrom-Json
    Assert-True ([bool]$v.salvaged) 'partial verdict flagged salvaged'
    Assert-Equal 1 $v.verdict.connections.Count 'only the covered key applied'
    Assert-Equal 'proca|1.2.3.4|443' $v.verdict.connections[0].key 'covered key is the answered one'
    Assert-Equal 1 @($v.uncovered_keys).Count 'one key left uncovered'
    Assert-Equal 'procb|evil.example|8443' @($v.uncovered_keys)[0] 'unanswered key goes to tier3'

    # --- salvage with FULL per-connection coverage but failed aggregate shape
    # (reviewer M2, 2026-08-28): used to exit 5 with a verdict.json missing
    # uncovered_keys, crashing the caller under StrictMode. All keys covered
    # = the rebuilt verdict is complete -> exit 0.
    $rc = Invoke-Launcher 'hangnosummary'
    Assert-Equal 0 $rc 'fully covered salvage with broken aggregate accepted as complete'
    $v = Get-Content (Join-Path $root 'escalations\20260827-000001-verdict.json') -Raw | ConvertFrom-Json
    Assert-Equal 2 $v.verdict.connections.Count 'all keys in the rebuilt verdict'
    Assert-True ([bool]$v.verdict.summary) 'summary rebuilt'
    Assert-Null $v.PSObject.Properties['uncovered_keys'] 'no uncovered_keys on complete acceptance'

    # --- salvage with a DUPLICATE key: clean then suspicious. The first-wins
    # dedup validated the key as clean and suppressed it (review 2026-09-26);
    # suspicious must win and the rebuilt verdict must be ALARM
    $rc = Invoke-Launcher 'hangdupe'
    Assert-Equal 0 $rc 'fully covered duplicate-key salvage accepted'
    $v = Get-Content (Join-Path $root 'escalations\20260827-000001-verdict.json') -Raw | ConvertFrom-Json
    Assert-Equal 'ALARM' $v.verdict.verdict 'duplicate key with a suspicious answer -> ALARM'
    Assert-Equal 2 $v.verdict.connections.Count 'one entry per packet key'
    $dup = @($v.verdict.connections | Where-Object key -eq 'proca|1.2.3.4|443')
    Assert-Equal 'suspicious' $dup[0].assessment 'suspicious wins over the earlier clean'

    # --- verdict schema is parseable AND enforced (reviewer M1: the cross-file
    # $ref made Test-Json fail with "Cannot parse the JSON schema", so nothing
    # was ever validated against it while the contract claimed otherwise) -----
    $vSchema = "$PSScriptRoot\..\schemas\verdict.schema.json"
    $goodV = '{"verdict":"CLEAN","summary":"ok","connections":[{"key":"a|1.2.3.4|443","assessment":"clean","reasons":["r"],"evidence":["e"]}]}'
    Assert-True (Test-Json -Json $goodV -SchemaFile $vSchema -ErrorAction SilentlyContinue) 'valid verdict passes the schema'
    $badV = '{"verdict":"CLEAN","summary":12345,"connections":[{"key":"a|1.2.3.4|443","assessment":"clean","reasons":["r"],"evidence":["e"]}]}'
    Assert-False (Test-Json -Json $badV -SchemaFile $vSchema -ErrorAction SilentlyContinue) 'non-string summary fails the schema'
    # wired into the launcher: a type-invalid verdict is exit 4, not accepted
    $rc = Invoke-Launcher 'badsummary'
    Assert-Equal 4 $rc 'schema-invalid verdict rejected by the launcher (exit 4)'

    # --- launch failure (F3) -------------------------------------------------
    $cfgBad = New-TestConfig -StateRoot $root -Override @{
        tier2 = @{ claude_exe = (Join-Path $root 'no-such-claude.exe') }
    }
    & pwsh -NoProfile -File $invoke -PacketPath $packetPath -ConfigPath $cfgBad | Out-Null
    Assert-Equal 3 $LASTEXITCODE 'missing exe exit 3 (F3)'
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
