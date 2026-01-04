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

        $comment = "BitLocker protection status is '$protStatusText' with $($v.EncryptionPercentage)% encrypted."
        $recommendation = $null

        if ($protStatusText -eq 'Off' -or $v.EncryptionPercentage -lt 100) {
            $recommendation = 'Enable BitLocker and ensure the volume is fully encrypted, especially for OS and data volumes containing sensitive information.'
        }
        elseif ($isOS -and -not $hasTPM -and -not $hasPIN) {
            $recommendation = 'For OS volumes, use TPM (and optionally TPM+PIN) as key protector instead of password-only where hardware supports it.'
        }
        elseif ($isOS -and $hasTPM -and -not $hasPIN) {
            $recommendation = 'Consider enabling TPM+PIN for the OS volume to provide stronger pre-boot authentication on sensitive endpoints.'
        }
        elseif (-not $hasRecoveryPassword) {
            $recommendation = 'Ensure a BitLocker recovery password is configured and properly backed up (e.g., in Active Directory or a secure vault).'
        }
        else {
            $recommendation = 'Review BitLocker settings regularly to ensure protectors (TPM, PIN, recovery key) still meet security requirements.'
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
