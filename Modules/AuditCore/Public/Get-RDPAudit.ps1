function Get-RDPAudit {
    [CmdletBinding()]
    param()

    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny  = (Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpEnabled = ($deny -eq 0)

    $rdpcfgkey = 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp'
    $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    $cfg = Get-ItemProperty -Path $rdpcfgkey -ErrorAction SilentlyContinue | Select-Object 'MinEncryptionLevel', 'SecurityLayer', 'UserAuthentication'
    $pol   = Get-ItemProperty -Path $polKey -ErrorAction SilentlyContinue

    $minEnc        = $cfg.MinEncryptionLevel
    $securityLayer = $cfg.SecurityLayer
    $userAuth      = $cfg.UserAuthentication
    $encryptRPC    = $pol.fEncryptRPCTraffic

    $minEncText = switch ($minEnc) {
        0 { '0 / None (chiffrement désactivé)' }
        1 { '1 / Low (client→serveur seulement)' }
        2 { '2 / Client Compatible' }
        3 { '3 / High (128 bits)' }
        4 { '4 / FIPS Compliant' }
        default { "$minEnc / Valeur inconnue" }
    }

    $securityLayerText = switch ($securityLayer) {
        0 { '0 / RDP Security (ancien, à éviter)' }
        1 { '1 / Négociation (RDP ou TLS selon support)' }
        2 { '2 / SSL/TLS uniquement' }
        default { "$securityLayer / Valeur inconnue" }
    }

    $userAuthText = switch ($userAuth) {
        0 { '0 / NLA non requis' }
        1 { '1 / NLA requis' }
        default { "$userAuth / Valeur inconnue" }
    }

    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $RA = (Get-ItemProperty -Path $lsaKey -Name 'DisableRestrictedAdmin' -ErrorAction SilentlyContinue).DisableRestrictedAdmin
    
    $disableRA = switch($RA){
        
        1{$true}
        0{$false}
        $null{"Key not found / Disabled by default"}
        Default{"Value unknown"}

    }

    [pscustomobject]@{
        RDPEnabled             = $rdpEnabled
        DisableRestrictedAdmin = $disableRA
        MinEncryptionLevel     = $minEncText
        SecurityLayer          = $securityLayerText
        UserAuthentication     = $userAuthText
        fEncryptRPCTraffic     = ($encryptRPC -eq 1)
    }
}
