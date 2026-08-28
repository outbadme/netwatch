# _testconfig.ps1 - builds a netwatch config file inside a test state root.
# Dot-source after _assert.ps1. Repo root derived from this file's location.

$script:RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

function New-TestConfig {
    # Returns the path of a config json written into $StateRoot\config.json.
    # $Override: hashtable of top-level keys merged over the defaults below.
    param(
        [Parameter(Mandatory)] [string]$StateRoot,
        [hashtable]$Override = @{}
    )
    $cfg = @{
        sample_interval_sec = 30
        debounce            = @{ min_samples = 2; min_age_sec = 60 }
        tier2               = @{
            min_interval_min   = 10
            wall_clock_cap_sec = 180
            max_turns          = 25
            batch_cap          = 20
            model              = 'sonnet'
            claude_exe         = 'auto'
            claude_args_prefix = @()
        }
        suppression_ttl_hours = 24
        classify = @{
            browser_attributed_ok = @('msedge', 'msedgewebview2', 'octium', 'octo browser')
            machine_notes         = @('test machine note')
        }
        sni = @{
            tshark_exe                   = (Join-Path $StateRoot 'no-such-tshark.exe')
            capture_ports                = @(443, 8443)
            http_ports                   = @(80)
            interfaces                   = @('test-nic0')   # pinned: never probe the host's adapters
            interface_settle_sec         = 60
            blind_after_sec              = 0                # off by default; blindness tests opt in
            restart_backoff_sec          = @(5, 30, 300)
            max_restarts_before_degraded = 5
        }
        own_ip = @{
            recorded_static      = @('203.0.113.10')
            redetect_interval_min = 60
        }
        retention_days   = @{ conn_logs = 14; op_logs = 14; escalations = 90; alarms = 365 }
        reputation_quota = @{ vt_per_day = 400; vt_per_min = 4; abuseipdb_per_day = 900 }
        paths = @{
            state_root = $StateRoot
            code_root  = $script:RepoRoot
            whitelist  = (Join-Path $StateRoot 'whitelist.json')
        }
    }
    foreach ($k in $Override.Keys) {
        if ($cfg[$k] -is [hashtable] -and $Override[$k] -is [hashtable]) {
            foreach ($k2 in $Override[$k].Keys) { $cfg[$k][$k2] = $Override[$k][$k2] }
        }
        else { $cfg[$k] = $Override[$k] }
    }
    $path = Join-Path $StateRoot 'config.json'
    $cfg | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}
