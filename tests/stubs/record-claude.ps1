# record-claude.ps1 - records argv + cwd to RECORD_CLAUDE_FILE and exits;
# stands in for the visible claude window in tier3 tests.
$out = @{
    args = $args
    cwd  = (Get-Location).Path
}
$out | ConvertTo-Json | Set-Content -LiteralPath $env:RECORD_CLAUDE_FILE
