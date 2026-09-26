# installutil.psm1 - helpers shared by the operator install scripts
# (enable-etw.ps1, enable-sysmon.ps1). Pure decisions are split from the
# machine changes so tests can cover them without admin rights.

Set-StrictMode -Version Latest

function Test-CertOrganization {
    # True when the certificate subject's O= attribute is EXACTLY $Organization.
    # A substring/regex match on the subject string accepted
    # 'O=Microsoft Corporation Evil' and 'OU=O=Microsoft Corporation'.
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)] [string]$Organization
    )
    $orgs = @(foreach ($rdn in $Certificate.SubjectName.EnumerateRelativeDistinguishedNames()) {
            if ($rdn.HasMultipleElements) { continue }            # multi-valued RDN: never a plain O=
            if ($rdn.GetSingleElementType().Value -eq '2.5.4.10') { $rdn.GetSingleElementValue() }
        })
    return ($orgs.Count -eq 1 -and $orgs[0] -ceq $Organization)
}

function Get-FileVersionNumber {
    # FileVersion of an executable as [version], $null when unreadable
    param([Parameter(Mandatory)] [string]$Path)
    try {
        $fv = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        return [version]::new($fv.FileMajorPart, $fv.FileMinorPart, $fv.FileBuildPart, $fv.FilePrivatePart)
    }
    catch { return $null }
}

function Get-ChannelMaxSize {
    # maxSize (bytes) from 'wevtutil gl <channel>' output lines, $null if absent
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$WevtutilOutput)
    foreach ($l in $WevtutilOutput) {
        if ($l -match '^\s*maxSize:\s*(\d+)\s*$') { return [long]$Matches[1] }
    }
    return $null
}

function Enable-EventChannel {
    # Enables a channel and grows its ring to at least $MinBytes. Never
    # shrinks an operator's larger setting (wevtutil sl /ms would). Throws on
    # any wevtutil failure - native errors do not stop a script by themselves.
    param(
        [Parameter(Mandatory)] [string]$Channel,
        [Parameter(Mandatory)] [long]$MinBytes
    )
    $cur = Get-ChannelMaxSize -WevtutilOutput @(wevtutil gl $Channel)
    if ($LASTEXITCODE -ne 0) { throw "wevtutil gl $Channel exited $LASTEXITCODE" }
    $slArgs = @('sl', $Channel, '/e:true')
    if ($null -eq $cur -or $cur -lt $MinBytes) { $slArgs += "/ms:$MinBytes" }
    & wevtutil @slArgs
    if ($LASTEXITCODE -ne 0) { throw "wevtutil $($slArgs -join ' ') exited $LASTEXITCODE" }
    $after = @(wevtutil gl $Channel)
    return [pscustomobject]@{
        channel  = $Channel
        enabled  = [bool]($after -match '^\s*enabled:\s*true')
        max_size = Get-ChannelMaxSize -WevtutilOutput $after
    }
}

Export-ModuleMember -Function Test-CertOrganization, Get-FileVersionNumber, Get-ChannelMaxSize, Enable-EventChannel
