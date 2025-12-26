function Get-LsassProtectionStatus {
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

    $runAsPPL = (Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    $useLogon = (Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    $desc = @()
    $reco = @()

    switch ($runAsPPL) {

        2 {
            $desc += 'LSA: LSA protection (RunAsPPL) enabled with Secure Boot required.'
            $reco += 'Keep LSA protection enabled with Secure Boot to harden LSASS against credential dumping.'
        }

        1 {
            $desc += 'LSA: LSA protection (RunAsPPL) enabled without Secure Boot required.'
            $reco += 'Consider enforcing LSA protection with Secure Boot where hardware/firmware support is available.'
        }

        Default {
            $desc += 'LSA: Unknown value or non-existent key; LSA protection is likely disabled.'
            $reco += 'Enable LSA protection (RunAsPPL = 1 or 2) via registry or GPO to protect LSASS from credential theft attacks.'
        }
    }

    switch ($useLogon) {

        1 {
            $desc += 'WDigest: UseLogonCredential = 1 (passwords may be stored in clear text in LSASS).'
            $reco += 'Disable WDigest by setting UseLogonCredential = 0 to prevent clear-text password storage in LSASS.'
            $Xml = [pscustomobject]@{
                Category    = "LsassProtection"
                Description = "Disable WDigest by setting UseLogonCredential = 0 to prevent clear-text password storage in LSASS."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
            }
            [void]$XmlList.Add($Xml)
        }

        0 {
            $desc += 'WDigest: UseLogonCredential = 0 (clear-text passwords are not stored).'
            $reco += 'Keep WDigest disabled (UseLogonCredential = 0) unless a documented legacy dependency requires it.'
        }

        Default {
            $desc += 'WDigest: UseLogonCredential key does not exist; default behavior may be unsafe on older systems.'
            $reco += 'Create the WDigest UseLogonCredential DWORD and set it to 0 to explicitly disable clear-text password storage.'
            $Xml = [pscustomobject]@{
                Category    = "LsassProtection"
                Description = "Disable WDigest by setting UseLogonCredential = 0 to prevent clear-text password storage in LSASS."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
            }
            [void]$XmlList.Add($Xml)
        }
    }

    $ProtectionStatus = [pscustomobject]@{
        LsaPath            = $lsaPath
        RunAsPPL           = $runAsPPL
        WDigestPath        = $wdigestPath
        UseLogonCredential = if ($useLogon -ne $null) { $useLogon } else { 'N/A' }
        Description        = $desc  -join ' | '
        Recommendation     = $reco  -join ' | '
    }

    $Output = [PSCustomObject]@{
        Value = $ProtectionStatus
        Xml = $XmlList
    }

    Return $Output
}
