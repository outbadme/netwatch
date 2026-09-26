# verify-packages.ps1 - integrity check for operator-dropped installers in
# install\packages\ (read-only; run before executing any installer).
# Checks: size + SHA256 vs the vendor SIGNATURES file + Authenticode.

#Requires -Version 7.6
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pkgDir = Join-Path $PSScriptRoot 'packages'
$exeName = 'Wireshark-4.6.8-x64.exe'
$exe = Join-Path $pkgDir $exeName
$sigFile = Join-Path $pkgDir 'SIGNATURES-4.6.8.txt'

$item = Get-Item -LiteralPath $exe
$sigLines = Get-Content -LiteralPath $sigFile

$sizeLine = @($sigLines | Where-Object { $_ -like "$exeName*bytes*" })[0]
$sizeExpected = [long][regex]::Match($sizeLine, '(\d+)\s*bytes').Groups[1].Value
$shaLine = @($sigLines | Where-Object { $_ -like "SHA256($exeName)=*" })[0]
$shaExpected = $shaLine.Split('=')[1].Trim().ToLowerInvariant()
$shaActual = (& certutil -hashfile $exe SHA256)[1].Trim().ToLowerInvariant()

$sig = Get-AuthenticodeSignature -LiteralPath $exe

[pscustomobject]@{
    file         = $item.Name
    size_ok      = ($item.Length -eq $sizeExpected)
    sha256_ok    = ($shaActual -eq $shaExpected)
    sha256       = $shaActual
    authenticode = "$($sig.Status)"
    signer       = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
} | ConvertTo-Json
