function Get-BitLockerAudit {
    [CmdletBinding()]
    param()

    $vols = Get-BitLockerVolume

    $Print = [System.Collections.ArrayList]@()

    foreach ($v in $vols) {
        $isOS  = ($v.VolumeType -eq 'OperatingSystem')
        $prot  = $v.KeyProtector

        $hasTPM = $prot | Where-Object KeyProtectorType -eq 'Tpm'
        $hasPIN = $prot | Where-Object KeyProtectorType -eq 'TpmPin'


        $BitLockerState = [pscustomobject]@{
            MountPoint        = $v.MountPoint
            VolumeType        = $v.VolumeType
            ProtectionStatus  = $v.ProtectionStatus
            EncryptionPercent = $v.EncryptionPercentage
            HasTPM            = [bool]$hasTPM
            HasPIN            = [bool]$hasPIN
        }

        [void]$Print.Add($BitLockerState)
    }

    Return $Print
}
