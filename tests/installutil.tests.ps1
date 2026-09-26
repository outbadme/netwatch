# installutil.tests.ps1 - pure helpers of the operator install scripts:
# exact signer organization, file version, wevtutil maxSize parsing.
. "$PSScriptRoot\_assert.ps1"
Import-Module "$PSScriptRoot\..\install\installutil.psm1" -Force

function New-TestCert([string]$Subject) {
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }
    finally { $key.Dispose() }
}

$ms = 'Microsoft Corporation'
Assert-True  (Test-CertOrganization -Certificate (New-TestCert "CN=Microsoft Windows, O=$ms, L=Redmond, C=US") -Organization $ms) 'exact O= accepted'
Assert-False (Test-CertOrganization -Certificate (New-TestCert "CN=x, O=$ms Evil, C=US") -Organization $ms) 'O= with a suffix rejected'
Assert-False (Test-CertOrganization -Certificate (New-TestCert "CN=x, OU=O=$ms, O=Evil") -Organization $ms) 'O= inside another attribute rejected'
Assert-False (Test-CertOrganization -Certificate (New-TestCert "CN=O=$ms") -Organization $ms) 'O= inside CN rejected'
Assert-False (Test-CertOrganization -Certificate (New-TestCert "CN=x, O=microsoft corporation") -Organization $ms) 'case differs -> rejected'

Assert-Equal 67108864 (Get-ChannelMaxSize -WevtutilOutput @('name: X', 'enabled: true', 'logging:', '  maxSize: 67108864')) 'maxSize parsed'
Assert-Null (Get-ChannelMaxSize -WevtutilOutput @('enabled: false')) 'no maxSize -> null'

$pwshExe = (Get-Process -Id $PID).Path
$v = Get-FileVersionNumber -Path $pwshExe
if ($IsWindows) { Assert-True ($v -ge [version]'7.0') "pwsh.exe FileVersion read ($v)" }
Assert-Null (Get-FileVersionNumber -Path (Join-Path $PSScriptRoot 'no-such.exe')) 'missing file -> null'

Complete-Tests
