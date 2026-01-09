function Get-ThirdPartyEncryptionIndicators {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    # Get computer model once
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $isVM = $cs.Model -match 'Virtual|VMware|Hyper-V|KVM|Xen'

    $vols = Get-CimInstance -ClassName Win32_Volume

    foreach ($v in $vols) {

        $isUnknown = -not $v.FileSystem -or $v.DriveType -eq 0

        $desc = @()
        $reco = @()

        if ($isUnknown) {
            $desc += "Les volumes sans systeme de fichiers connu ou avec un type de lecteur inconnu."
            $reco += "Verifier si ce volume est protege par un produit de chiffrement de disque complet tiers (par exemple Sophos, McAfee, etc.).'"
        }

        if ($isVM) {
            $desc += "Machine virtuelle detectee en fonction du modele systeme."
            $reco += "Verifier si le chiffrement est applique au niveau de l'hyperviseur (VHD/VMDK chiffres, vTPM, politique de chiffrement basee sur l'hote)."
        }

        if (-not $desc) {
            $desc += "Aucun indicateur de chiffrement tiers specifique detecte sur ce volume."
            $reco += "Revoir votre politique globale de chiffrement de disque (BitLocker, FDE tiers ou chiffrement au niveau de l'hyperviseur) pour cet hote."
        }

        $Indicators = [pscustomobject]@{
            DeviceID                     = $v.DeviceID
            DriveLetter                  = $v.DriveLetter
            Label                        = $v.Label
            FileSystem                   = $v.FileSystem
            DriveType                    = $v.DriveType
            PossiblyEncryptedThirdParty  = $isUnknown
            IsVM                         = $isVM
            Description                  = $desc -join '; '
            Recommendation               = $reco  -join ' '
        }

        [void]$Print.Add($Indicators)
    }

    return $Print
}

