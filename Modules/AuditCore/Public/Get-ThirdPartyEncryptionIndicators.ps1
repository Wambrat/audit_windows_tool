function Get-ThirdPartyEncryptionIndicators {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $vols = Get-CimInstance -ClassName Win32_Volume

    foreach ($v in $vols) {
        $isUnknown = -not $v.FileSystem -or $v.DriveType -eq 0
        $isVM      = (Get-CimInstance -ClassName Win32_ComputerSystem).Model -match 'Virtual|VMware|Hyper-V|KVM|Xen'

        $desc = @()
        if ($isUnknown) {
            $desc += 'Partition without a known file system: check for third-party encryption (Sophos, McAfee, etc.)'
        }
        if ($isVM) {
            $desc += 'Virtual machine: check encryption at the hypervisor level (encrypted disks, vTPM, etc.)'
        }
        if (-not $desc) {
            $desc += 'Nothing unusual detected, check the overall encryption policy'
        }

        $Indicators = [pscustomobject]@{
            DeviceID       = $v.DeviceID
            DriveLetter    = $v.DriveLetter
            Label          = $v.Label
            FileSystem     = $v.FileSystem
            DriveType      = $v.DriveType
            PossiblyEncryptedThirdParty = $isUnknown
            IsVM           = $isVM
            Description = $desc -join '; '
        }

        [void]$Print.Add($Indicators)
    }

    Return $Print
}
