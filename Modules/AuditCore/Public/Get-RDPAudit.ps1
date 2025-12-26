function Get-RDPAudit {
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $deny  = (Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpEnabled = ($deny -eq 0)

    $rdpcfgkey = 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp'
    $polKey    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

    $cfg = Get-ItemProperty -Path $rdpcfgkey -ErrorAction SilentlyContinue |
           Select-Object 'MinEncryptionLevel','SecurityLayer','UserAuthentication'
    $pol = Get-ItemProperty -Path $polKey -ErrorAction SilentlyContinue

    $minEnc        = $cfg.MinEncryptionLevel
    $securityLayer = $cfg.SecurityLayer
    $userAuth      = $cfg.UserAuthentication
    $encryptRPC    = $pol.fEncryptRPCTraffic

    $minEncText = switch ($minEnc) {
        0 { '0 / None (encryption disabled)' }
        1 { '1 / Low (client to server only)' }
        2 { '2 / Client compatible' }
        3 { '3 / High (128-bit encryption)' }
        4 { '4 / FIPS compliant' }
        default { "$minEnc / Unknown value" }
    }

    $securityLayerText = switch ($securityLayer) {
        0 { '0 / RDP Security (legacy, should be avoided)' }
        1 { '1 / Negotiation (RDP or TLS depending on support)' }
        2 { '2 / SSL/TLS only' }
        default { "$securityLayer / Unknown value" }
    }

    $userAuthText = switch ($userAuth) {
        0 { '0 / NLA not required' }
        1 { '1 / NLA required' }
        default { "$userAuth / Unknown value" }
    }

    # Restricted Admin / Remote Credential Guard
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $RA     = (Get-ItemProperty -Path $lsaKey -Name 'DisableRestrictedAdmin' -ErrorAction SilentlyContinue).DisableRestrictedAdmin

    $disableRA = switch ($RA) {
        1      { $true  }
        0      { $false }
        $null  { 'Key not found / Disabled by default' }
        Default{ "Unknown value ($RA)" }
    }

    # Build a simple recommendation block
    $reco = @()

    if ($rdpEnabled) {
        $reco += 'RDP is enabled; ensure it is only exposed from dedicated admin networks or via jump hosts/VPN.'

        if ($securityLayer -ne 2) {
            $reco += 'Set SecurityLayer = 2 (SSL/TLS) to enforce TLS for RDP connections.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Security Layer"
                Description = "Set SecurityLayer = 2 (SSL/TLS) to enforce TLS for RDP connections."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($minEnc -lt 3) {
            $reco += 'Use at least High (3) or FIPS (4) encryption level for RDP sessions to strengthen confidentiality.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Encryption level"
                Description = "Set encryption level to High (3) for RDP sessions" 
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($userAuth -ne 1) {
            $reco += 'Require Network Level Authentication (UserAuthentication = 1) to reduce RDP pre-authentication exposure.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - Network Level Authentication"
                Description = "Set Network Level Authentication (UserAuthentication = 1) to reduce RDP pre-authentication exposure."
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
            }
            [void]$XmlList.Add($Xml)
        }

        if ($encryptRPC -ne 1) {
            $reco += 'Enable fEncryptRPCTraffic = 1 via policy to enforce RDP/RPC encryption.'
            $Xml = [pscustomobject]@{
                Category    = "RDPAudit - RDP/RPC encryption"
                Description = "Enable fEncryptRPCTraffic = 1 via policy to enforce RDP/RPC encryption."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fEncryptRPCTraffic -Value 1"
            }
            [void]$XmlList.Add($Xml)
        }

    }
    else {
        $reco += 'RDP is disabled at the OS level (fDenyTSConnections != 0); keep it disabled if not strictly required.'
    }



    $RDPAudit = [pscustomobject]@{
        RDPEnabled             = $rdpEnabled
        DisableRestrictedAdmin = $disableRA
        MinEncryptionLevel     = $minEncText
        SecurityLayer          = $securityLayerText
        UserAuthentication     = $userAuthText
        fEncryptRPCTraffic     = ($encryptRPC -eq 1)
        Recommendation         = $reco -join ' | '
    }

    $Output = [PSCustomObject]@{
        Value = $RDPAudit
        Xml = $XmlList
    }

    return $Output

}
