function Get-SMBAudit {
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $LanManServer = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\' `
                     -ErrorAction SilentlyContinue |
                     Select-Object EnableSecuritySignature, RequireSecuritySignature

    $LanManWorkStation = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' `
                          -ErrorAction SilentlyContinue |
                          Select-Object EnableSecuritySignature, RequireSecuritySignature

    $SMBInfo = Get-SmbServerConfiguration

    $SMBA = [pscustomobject]@{
        SMBv1State               = $SMBInfo.EnableSMB1Protocol
        SMBv2State               = $SMBInfo.EnableSMB2Protocol
        EnableSecuritySignature  = $SMBInfo.EnableSecuritySignature
        RequireSecuritySignature = $SMBInfo.RequireSecuritySignature
        LanManServer             = $LanManServer
        LanManWorkStation        = $LanManWorkStation
        Comment                  = $null
        Recommendation           = $null
    }

    $comments = @()
    $reco     = @()

    if($SMBInfo.EnableSMB1Protocol) {
        $comments += 'Le protocole SMBv1 est active sur ce serveur.'
        $reco     += "Desactivez SMBv1 (EnableSMB1Protocol = $false) pour supprimer un protocole ancien et vulnerable de l'environnement."
        $Xml = [pscustomobject]@{
                Category    = "SMBv1"
                Description = "Desactivez SMBv1 (EnableSMB1Protocol = $false) pour supprimer un protocole ancien et vulnerable de l'environnement."
                Command     = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
            }
        [void]$XmlList.Add($xml)
    }else{
        $comments += 'Le protocole SMBv1 est desactive sur ce serveur.'
    }

    if(-not $SMBInfo.EnableSMB2Protocol){
        $comments += 'SMBv2/3 est desactive.'
        $reco     += 'Activez SMBv2/3 et migrez toutes les dependances SMBv1 restantes avant de supprimer completement SMBv1.'
        $Xml = [pscustomobject]@{
                Category    = "SMBv2"
                Description = "Activez SMBv2 et migrez toutes les dependances SMBv1 restantes avant de supprimer completement SMBv1."
                Command     = "Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force"
            }
        [void]$XmlList.Add($xml)
    }

    if(-not $SMBInfo.RequireSecuritySignature){
        $comments += "La signature SMB n'est pas requise pour les connexions au serveur."
        $reco     += 'Configure RequireSecuritySignature = $true on servers and align client settings to reduce NTLM relay and tampering risks.'
        $Xml = [pscustomobject]@{
                Category    = "SMB Signing"
                Description = "Configurez RequireSecuritySignature = $true sur les serveurs et alignez les parametres du client pour reduire les risques de relais NTLM et de falsification."
                Command     = "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
            }
        [void]$XmlList.Add($xml)
    }else{
        $comments += 'La signature SMB est requise pour les connexions au serveur.'
    }

    $SMBA.Comment        = $comments -join ' | '
    $SMBA.Recommendation = if ($reco.Count -gt 0) {
        $reco -join ' | '
    }else{
        'La configuration SMB semble conforme aux normes de securite courantes (SMBv1 desactive, SMBv2/3 active, signature requise).'
    }

    $Output = [PSCustomObject]@{
        Value = $SMBA
        Xml = $XmlList
    }

    return $Output
}

