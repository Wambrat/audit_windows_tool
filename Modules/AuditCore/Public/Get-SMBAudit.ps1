function Get-SMBAudit {
    [CmdletBinding()]
    param()

    $LanManServer = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\ | Select-Object EnableSecuritySignature, RequireSecuritySignature
    $LanManWorkStation = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\ | Select-Object EnableSecuritySignature, RequireSecuritySignature

    $SMBInfo = Get-SmbServerConfiguration

    $SMBA = [pscustomobject]@{
            SMBv1State               = $SMBInfo.EnableSMB1Protocol
            SMBV2State               = $SMBInfo.EnableSMB2Protocol
            EnableSecuritySignature  = $SMBInfo.EnableSecuritySignature
            RequireSecuritySignature = $SMBInfo.RequireSecuritySignature
            LanManServer             = $LanManServer
            LanManWorkStation        = $LanManWorkStation

        }

    Return $SMBA
}