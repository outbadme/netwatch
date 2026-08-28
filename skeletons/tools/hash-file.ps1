# hash-file.ps1 — Tier-2 MCP tool backend. READ-ONLY. JSON on stdout.

#Requires -Version 7
param([Parameter(Mandatory)] [string]$Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Out-Result($obj) { $obj | ConvertTo-Json -Depth 4; exit 0 }

if (-not [IO.Path]::IsPathRooted($Path))                 { Out-Result @{ error = 'path must be absolute' } }
if ($Path -match '(?i)\\Users\\[^\\]+\\Downloads(\\|$)') { Out-Result @{ error = 'path denied by policy' } }
if (-not (Test-Path -LiteralPath $Path -PathType Leaf))  { Out-Result @{ error = 'file not found' } }

$item = Get-Item -LiteralPath $Path
Out-Result @{
    path           = $Path
    sha256         = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes     = $item.Length
    last_write_utc = $item.LastWriteTimeUtc.ToString('o')
    # Comparison against vendor/upstream hashes is Tier-3 (human) work — this
    # tool only produces the local fact.
}
