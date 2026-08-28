# enrich.tests.ps1 - own-IP lifecycle (F7/F8 fail-closed), lookup exclusions,
# Cymru ASN parse.
. "$PSScriptRoot\_assert.ps1"
. "$PSScriptRoot\_testconfig.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\state.psm1" -Force
Import-Module "$PSScriptRoot\..\src\tier1\modules\enrich.psm1" -Force

$root = New-TestStateRoot
try {
    $cfgPath = New-TestConfig -StateRoot $root
    $cfg = Get-NetwatchConfig -Path $cfgPath
    Initialize-StateRoot -Config $cfg

    # --- own-IP detect via injected resolver ---------------------------------
    Update-OwnIp -Config $cfg -ResolveFn { @('1.2.3.4') }
    $own = Get-Content (Join-Path $root 'state\ownip.json') -Raw | ConvertFrom-Json
    Assert-True ('1.2.3.4' -in $own.detected) 'detected ip stored'
    Assert-True ('203.0.113.10' -in $own.recorded_static) 'static recorded'

    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-True ('1.2.3.4' -in $ex) 'detected in exclusions'
    Assert-True ('203.0.113.10' -in $ex) 'static in exclusions'

    # --- IP change: old value keeps 7-day grace (F8) -------------------------
    Update-OwnIp -Config $cfg -ResolveFn { @('5.6.7.8') }
    $own = Get-Content (Join-Path $root 'state\ownip.json') -Raw | ConvertFrom-Json
    Assert-True ('5.6.7.8' -in $own.detected) 'new ip detected'
    Assert-True ('1.2.3.4' -in @($own.previous | ForEach-Object ip)) 'old ip retired to previous'
    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-True ('1.2.3.4' -in $ex) 'retired ip still excluded (grace)'
    Assert-True ('5.6.7.8' -in $ex) 'new ip excluded'

    # expired grace entry drops out
    $own.previous[0].retired_at = '2020-01-01T00:00:00Z'
    $own | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root 'state\ownip.json')
    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-False ('1.2.3.4' -in $ex) 'grace expired, old ip dropped'

    # --- resolver failure: fail closed (F7) ----------------------------------
    Update-OwnIp -Config $cfg -ResolveFn { throw 'dns down' }
    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-True ('5.6.7.8' -in $ex) 'last-known kept on failure'
    Assert-True ('203.0.113.10' -in $ex) 'static kept on failure'
    Assert-True ($ex.Count -ge 2) 'exclusion set never empty'

    # old-format/foreign ownip.json (missing fields) must not crash the
    # monitor at startup under StrictMode (reviewer NOTE, 2026-08-28) -
    # rebuild instead, carrying over what exists
    '{"detected":["9.9.9.9"],"last_known":["9.9.9.9"]}' |
        Set-Content (Join-Path $root 'state\ownip.json')
    Update-OwnIp -Config $cfg -ResolveFn { @('7.7.7.7') }
    $own = Get-Content (Join-Path $root 'state\ownip.json') -Raw | ConvertFrom-Json
    Assert-True ('7.7.7.7' -in $own.detected) 'old-format state rebuilt, detection continues'
    Assert-True ('9.9.9.9' -in @($own.previous | ForEach-Object ip)) 'pre-existing detected ip retired with grace'

    # ownip.json missing entirely -> static still excluded (fail closed)
    Remove-Item (Join-Path $root 'state\ownip.json')
    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-True ('203.0.113.10' -in $ex) 'static excluded with no state file'

    # --- Test-ExcludedFromLookup ---------------------------------------------
    Update-OwnIp -Config $cfg -ResolveFn { @('5.6.7.8') }
    $ex = Get-OwnIpExclusions -Config $cfg
    Assert-NotNull (Test-ExcludedFromLookup -Ip '203.0.113.10' -Exclusions $ex) 'own static excluded'
    Assert-NotNull (Test-ExcludedFromLookup -Ip '10.1.1.1' -Exclusions $ex) 'rfc1918 excluded'
    Assert-NotNull (Test-ExcludedFromLookup -Ip '100.64.0.10' -Exclusions $ex) 'tailscale cgnat excluded'
    Assert-Null (Test-ExcludedFromLookup -Ip '8.8.8.8' -Exclusions $ex) 'public ip allowed'

    # --- Cymru parse with canned resolver ------------------------------------
    $canned = {
        param($name)
        if ($name -like '*.origin.asn.cymru.com') { return '23028 | 216.90.108.0/24 | US | arin | 1998-09-25' }
        if ($name -like 'AS23028.*')              { return '23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US' }
        throw "unexpected query $name"
    }
    $asn = Get-CymruAsn -Ip '216.90.108.4' -ResolveFn $canned
    Assert-Equal 23028 $asn.asn 'asn parsed'
    Assert-Equal 'US' $asn.as_country 'country parsed'
    Assert-True ($asn.as_name -like '*TEAM-CYMRU*') 'as name parsed'

    # failure -> $null, never throws
    Assert-Null (Get-CymruAsn -Ip '216.90.108.4' -ResolveFn { throw 'dns down' }) 'lookup failure yields null'

    # --- live positive control (network) -------------------------------------
    # Machine rule: prove the real lookup path works before trusting it in
    # production. If the network is down this is REPORTED, never silently green.
    $live = Get-CymruAsn -Ip '8.8.8.8'
    if ($null -eq $live) {
        Write-Host 'WARNING: LIVE CYMRU CHECK NOT RUN (dns lookup failed) - rerun with network before deploy' -ForegroundColor Yellow
    }
    else {
        Assert-Equal 15169 $live.asn 'live: 8.8.8.8 is AS15169 (Google)'
        Write-Host "live cymru ok: AS$($live.asn) $($live.as_name)"
    }
}
finally {
    Remove-TestStateRoot $root
}
Complete-Tests
