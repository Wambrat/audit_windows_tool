function Get-BitLockerAudit {
    [CmdletBinding()]
    param()

    $vols = Get-BitLockerVolume
    $Print = [System.Collections.ArrayList]@()

    foreach ($v in $vols) {

        $isOS = ($v.VolumeType -eq 'OperatingSystem')
        $prot = $v.KeyProtector

        $hasTPM = $prot | Where-Object KeyProtectorType -eq 'Tpm'
        $hasPIN = $prot | Where-Object KeyProtectorType -eq 'TpmPin'
        $hasPassword = $prot | Where-Object KeyProtectorType -eq 'Password'
        $hasRecoveryPassword = $prot | Where-Object KeyProtectorType -eq 'RecoveryPassword'

        $protStatusText = switch ($v.ProtectionStatus) {
            0 { 'Off' }
            1 { 'On' }
            2 { 'Suspended' }
            default { "Unknown ($($v.ProtectionStatus))" }
        }

        $comment = "La Protection BitLocker est '$protStatusText' avec $($v.EncryptionPercentage)% de chiffrement."
        $recommendation = $null

        if ($protStatusText -eq 'Off' -or $v.EncryptionPercentage -lt 100) {
            $recommendation = "Activer BitLocker et assurer que le volume est pleinement chiffre, en particulier pour les volumes OS et de donnees contenant des informations sensibles."
        }
        elseif ($isOS -and -not $hasTPM -and -not $hasPIN) {
            $recommendation = "Pour les volumes de systeme d'exploitation, utilisez TPM (et eventuellement TPM+PIN) comme protecteur de cle au lieu d'un mot de passe uniquement lorsque le materiel le prend en charge."
        }
        elseif ($isOS -and $hasTPM -and -not $hasPIN) {
            $recommendation = "Envisagez d'activer TPM+PIN pour le volume du systeme d'exploitation afin de fournir une authentification prealable au demarrage plus forte sur les points de terminaison sensibles."
        }
        elseif (-not $hasRecoveryPassword) {
            $recommendation = "Assurez-vous qu'un mot de passe de recuperation BitLocker est configure et correctement sauvegarde (par exemple, dans Active Directory ou un coffre-fort securise)."
        }
        else {
            $recommendation = "Revoir regulierement les parametres BitLocker pour s'assurer que les protecteurs (TPM, PIN, cle de recuperation) respectent toujours les exigences de securite."
        }

        $BitLockerState = [pscustomobject]@{
            MountPoint         = $v.MountPoint
            VolumeType         = $v.VolumeType
            ProtectionStatus   = $protStatusText
            EncryptionPercent  = $v.EncryptionPercentage
            HasTPM             = [bool]$hasTPM
            HasPIN             = [bool]$hasPIN
            HasPassword        = [bool]$hasPassword
            HasRecoveryPassword= [bool]$hasRecoveryPassword
            Comment            = $comment
            Recommendation     = $recommendation
        }

        [void]$Print.Add($BitLockerState)
    }

    return $Print
}

