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
        $comments += 'SMBv1 is enabled on this server.'
        $reco     += 'Disable SMBv1 (EnableSMB1Protocol = $false) to remove a legacy and vulnerable protocol from the environment.'
        $Xml = [pscustomobject]@{
                Category    = "SMBv1"
                Description = "Disable SMBv1 (EnableSMB1Protocol = $false) to remove a legacy and vulnerable protocol from the environment."
                Command     = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
            }
        [void]$XmlList.Add($xml)
    }else{
        $comments += 'SMBv1 is disabled on this server.'
    }

    if(-not $SMBInfo.EnableSMB2Protocol){
        $comments += 'SMBv2/3 is disabled.'
        $reco     += 'Enable SMBv2/3 and migrate any remaining SMBv1 dependencies before fully deprecating SMBv1.'
        $Xml = [pscustomobject]@{
                Category    = "SMBv2"
                Description = "Enable SMBv2 and migrate any remaining SMBv1 dependencies before fully deprecating SMBv1."
                Command     = "Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force"
            }
        [void]$XmlList.Add($xml)
    }

    if(-not $SMBInfo.RequireSecuritySignature){
        $comments += 'SMB signing is not required for server connections.'
        $reco     += 'Configure RequireSecuritySignature = $true on servers and align client settings to reduce NTLM relay and tampering risks.'
        $Xml = [pscustomobject]@{
                Category    = "SMB signing"
                Description = "Configure RequireSecuritySignature = $true on servers and align client settings to reduce NTLM relay and tampering risks."
                Command     = "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"
            }
        [void]$XmlList.Add($xml)
    }else{
        $comments += 'SMB signing is required for server connections.'
    }

    $SMBA.Comment        = $comments -join ' | '
    $SMBA.Recommendation = if ($reco.Count -gt 0) {
        $reco -join ' | '
    }else{
        'SMB configuration appears aligned with common hardening baselines (SMBv1 disabled, SMBv2/3 enabled, signing required).'
    }

    $Output = [PSCustomObject]@{
        Value = $SMBA
        Xml = $XmlList
    }

    return $Output
}
