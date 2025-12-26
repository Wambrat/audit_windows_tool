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
            $desc += 'Volume without a known file system or with an unknown drive type.'
            $reco += 'Verify whether this volume is protected by a third-party full disk encryption product (e.g. Sophos, McAfee, etc.).'
        }

        if ($isVM) {
            $desc += 'Virtual machine detected based on system model.'
            $reco += 'Check if encryption is enforced at the hypervisor level (encrypted VHD/VMDK, vTPM, host-based encryption policy).'
        }

        if (-not $desc) {
            $desc += 'No specific third-party encryption indicators detected on this volume.'
            $reco += 'Review your global disk encryption policy (BitLocker, third-party FDE, or hypervisor-level encryption) for this host.'
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
