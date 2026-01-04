function Get-LsassProtectionStatus2 {
    [CmdletBinding()]
    param()

    $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

    $runAsPPL = (Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    $useLogon = (Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    $XmlList = [System.Collections.ArrayList]@()

    $desc = @()
    $reco = @()

    switch ($runAsPPL) {
        2 {
            $desc += 'LSA protection (RunAsPPL) is enabled with Secure Boot lock.'
            $reco += 'Keep LSA protection with Secure Boot enabled to harden LSASS against credential dumping.'
        }
        1 {
            $desc += 'LSA protection (RunAsPPL) is enabled without Secure Boot lock.'
            $reco += 'Consider enforcing LSA protection with Secure Boot for stronger protection where hardware supports it.'
        }
        Default {
            $desc += 'LSA protection (RunAsPPL) is not explicitly enabled (value unknown or key missing).'
            $reco += 'Enable LSA protection (RunAsPPL = 1 or 2) to protect LSASS from credential theft attacks.'
            $Xml = [pscustomobject]@{
                Category    = "LSA protection"
                Description = "Enable LSA protection with Secure Boot lock to protect LSASS from credential theft attacks."
                Command     = "Set-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -Value 2"
            }
            [void]$XmlList.Add($xml)
        }
    }

    switch ($useLogon) {
        1 {
            $desc += 'WDigest UseLogonCredential = 1 (passwords may be stored in clear text in LSASS).'
            $reco += 'Disable WDigest by setting UseLogonCredential = 0 to avoid storing clear-text passwords in LSASS.'
        }
        0 {
            $desc += 'WDigest UseLogonCredential = 0 (clear-text passwords are not stored).'
            $reco += 'Keep WDigest disabled (UseLogonCredential = 0) unless a specific legacy requirement is documented.'
        }
        Default {
            $desc += 'WDigest UseLogonCredential not found, default behavior may allow insecure storage on older systems.'
            $reco += 'Create the WDigest UseLogonCredential DWORD and set it to 0 to explicitly disable clear-text password storage.'
            $Xml = [pscustomobject]@{
                Category    = "WDigest"
                Description = "Create the WDigest UseLogonCredential DWORD and set it to 0 to explicitly disable clear-text password storage."
                Command     = "set-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -Value 0"
            }
            [void]$XmlList.Add($xml)
        }
    }

    $LSASS = [pscustomobject]@{
        LsaPath            = $lsaPath
        RunAsPPL           = $runAsPPL
        WDigestPath        = $wdigestPath
        UseLogonCredential = if ($useLogon -ne $null) { $useLogon } else { 'N/A' }
        Description        = $desc -join ' | '
        Recommendation     = $reco  -join ' | '
    }

    $Output = [PSCustomObject]@{
        Value = $LSASS
        Xml = $XmlList
    }

    return $Output
}
