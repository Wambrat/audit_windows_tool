function Get-LsassProtectionStatus {
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $lsaPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

    $runAsPPL = (Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    $useLogon = (Get-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential

    $desc = @()
    $reco = @()

    switch ($runAsPPL) {

        2 {
            $desc += "LSA: La protection LSA (RunAsPPL) est activee avec Secure Boot requis."
            $reco += "Gardez la protection LSA activee avec Secure Boot pour renforcer LSASS contre le vidage des informations d identification."
        }

        1 {
            $desc += "LSA : la protection LSA (RunAsPPL) est activee sans Secure Boot requis."
            $reco += "Considerer l'application de la protection LSA avec Secure Boot lorsque le materiel/firmware le permet."
        }

        Default {
            $desc += "LSA: Valeur inconnue ou cle inexistante; la protection LSA est probablement desactivee."
            $reco += "Activez la protection LSA (RunAsPPL = 1 ou 2) via le registre ou la GPO pour proteger LSASS contre les attaques de vol d informations d identification."
        }
    }

    switch ($useLogon) {

        1 {
            $desc += "WDigest: UseLogonCredential = 1 (les mots de passe peuvent etre stockes en texte clair dans LSASS)."
            
            $reco += "Desactiver WDigest en definissant UseLogonCredential = 0 pour eviter le stockage des mots de passe en texte clair dans LSASS."
            $Xml = [pscustomobject]@{
                Category    = "LsassProtection"
                Description = "Desactiver WDigest en definissant UseLogonCredential = 0 pour eviter le stockage des mots de passe en texte clair dans LSASS."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
            }
            [void]$XmlList.Add($Xml)
        }

        0 {
            $desc += "WDigest : UseLogonCredential = 0 (les mots de passe en texte clair ne sont pas stockes)."
            $reco += "Gardez WDigest desactive (UseLogonCredential = 0) sauf si une dependance hereditee documentee l'exige."
        }

        Default {
            $desc += "WDigest : la cle UseLogonCredential n'existe pas ; le comportement par defaut peut etre non securise sur les anciens systemes."
            $reco += "Creez la valeur DWORD UseLogonCredential de WDigest et definiissez-la a 0 pour desactiver explicitement le stockage des mots de passe en texte clair."
            $Xml = [pscustomobject]@{
                Category    = "LsassProtection"
                Description = "Desactiver WDigest en definissant UseLogonCredential = 0 pour eviter le stockage des mots de passe en texte clair dans LSASS."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0"
            }
            [void]$XmlList.Add($Xml)
        }
    }

    $ProtectionStatus = [pscustomobject]@{
        LsaPath            = $lsaPath
        RunAsPPL           = $runAsPPL
        WDigestPath        = $wdigestPath
        UseLogonCredential = if ($useLogon) { $useLogon } else { "N/A" }
        Description        = $desc  -join " | "
        Recommendation     = $reco  -join " | "
    }

    $Output = [PSCustomObject]@{
        Value = $ProtectionStatus
        Xml = $XmlList
    }

    Return $Output
}

