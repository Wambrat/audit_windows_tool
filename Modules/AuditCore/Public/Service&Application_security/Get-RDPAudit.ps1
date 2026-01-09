function Get-RDPAudit {
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny  = (Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpEnabled = ($deny -eq 0)

    $rdpcfgkey = 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp'
    $polKey    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    $cfg = Get-ItemProperty -Path $rdpcfgkey -ErrorAction SilentlyContinue |
           Select-Object 'MinEncryptionLevel','SecurityLayer','UserAuthentication'
    $pol = Get-ItemProperty -Path $polKey -ErrorAction SilentlyContinue

    $minEnc        = $cfg.MinEncryptionLevel
    $securityLayer = $cfg.SecurityLayer
    $userAuth      = $cfg.UserAuthentication
    $encryptRPC    = $pol.fEncryptRPCTraffic

    $minEncText = switch ($minEnc) {
        0 { '0 / Aucun (chiffrement desactive)' }
        1 { '1 / Faible (client vers serveur uniquement)' }
        2 { '2 / Compatible avec les clients' }
        3 { '3 / Haute (chiffrement 128 bits)' }
        4 { '4 / Conforme FIPS' }
        default { "$minEnc / Valeur inconnue" }
    }

    $securityLayerText = switch ($securityLayer) {
        0 { '0 / Securite RDP (ancienne version, a eviter)' }
        1 { '1 / Negociation (RDP ou TLS selon le support)' }
        2 { '2 / SSL/TLS uniquement' }
        default { "$securityLayer / Valeur inconnue" }
    }

    $userAuthText = switch ($userAuth) {
        0 { '0 / NLA non requis' }
        1 { '1 / NLA requis' }
        default { "$userAuth / Valeur inconnue" }
    }

    # Restricted Admin / Remote Credential Guard
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $RA     = (Get-ItemProperty -Path $lsaKey -Name 'DisableRestrictedAdmin' -ErrorAction SilentlyContinue).DisableRestrictedAdmin

    $disableRA = switch ($RA) {
        1      { $true  }
        0      { $false }
        $null  { 'Cle introuvable / Desactivee par defaut' }
        Default{ "Valeur inconnue ($RA)" }
    }

    # Build a simple recommendation block
    $reco = @()

    if ($rdpEnabled) {
        $reco += "Le protocole RDP est active ; assurez-vous qu'il ne soit accessible que depuis des reseaux d'administration dedies ou via des serveurs de rebond/VPN."

        if ($securityLayer -ne 2) {
            $reco += 'Definissez SecurityLayer = 2 (SSL/TLS) pour imposer TLS pour les connexions RDP.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Security Layer"
                Description = "Definissez SecurityLayer = 2 (SSL/TLS) pour imposer TLS pour les connexions RDP."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($minEnc -lt 3) {
            $reco += 'Utilisez au moins un niveau de chiffrement eleve (3) ou FIPS (4) pour les sessions RDP afin de renforcer la confidentialite.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Encryption level"
                Description = "Utilisez au moins un niveau de chiffrement eleve (3) ou FIPS (4) pour les sessions RDP" 
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($userAuth -ne 1) {
            $reco += "Exiger une authentification au niveau du reseau (UserAuthentication = 1) pour reduire l'exposition a la pre-authentification RDP."
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Network Level Authentication"
                Description = "Configurez l'authentification au niveau du reseau (UserAuthentication = 1) pour reduire l'exposition a la pre-authentification RDP."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($encryptRPC -ne 1) {
            $reco += 'Activez fEncryptRPCTraffic = 1 via la strategie pour appliquer le chiffrement RDP/RPC.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - RDP/RPC encryption"
                Description = "Activez fEncryptRPCTraffic = 1 via la strategie pour appliquer le chiffrement RDP/RPC."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fEncryptRPCTraffic -Value 1"
            }
            [void]$XmlList.Add($Xml)
        }

    }
    else {
        $reco += "Le protocole RDP est desactive au niveau du systeme d'exploitation (fDenyTSConnections != 0) ; laissez-le desactive s'il n'est pas strictement necessaire."
    }



    $RDPAudit = [pscustomobject]@{
        RDPEnabled             = $rdpEnabled
        DisableRestrictedAdmin = $disableRA
        MinEncryptionLevel     = $minEncText
        SecurityLayer          = $securityLayerText
        UserAuthentication     = $userAuthText
        fEncryptRPCTraffic     = ($encryptRPC -eq 1)
        Recommendation         = $reco -join ' | '
    }

    $Output = [PSCustomObject]@{
        Value = $RDPAudit
        Xml = $XmlList
    }

    return $Output

}

