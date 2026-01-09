function Get-VPNStatus {
    [CmdletBinding()]
    param()

    # Interfaces type VPN/TAP/TUN actives
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Status -eq 'Up' -and
                    ($_.InterfaceDescription -match 'VPN' -or
                     $_.Name -match 'VPN' -or
                     $_.InterfaceDescription -match 'TAP' -or
                     $_.InterfaceDescription -match 'TUN')
                } |
                Select-Object Name, InterfaceDescription, Status, MacAddress

    $hasVpnAdapters = $adapters.Count -gt 0

    # Profils VPN natifs Windows
    $vpnProfiles = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
    $activeProfiles = $vpnProfiles | Where-Object { $_.ConnectionStatus -eq 'Connected' }

    $hasVpnProfiles       = $vpnProfiles.Count -gt 0
    $hasActiveVpnProfiles = $activeProfiles.Count -gt 0

    # Description globale
    $parts = @()

    if ($hasVpnAdapters) {
        $parts += "$($adapters.Count) Interface(s) VPN/TAP/TUN detectee(s) (Statut = Actif)"
    } else {
        $parts += "0 interface(s) VPN/TAP/TUN detectee(s)"
    }

    if ($hasVpnProfiles) {
        $parts += "$($vpnProfiles.Count) VPN profile(s) configured via Windows VPN client"
    } else {
        $parts += "0 profil(s) VPN configure(s) via le client VPN Windows"
    }

    if ($hasActiveVpnProfiles) {
        $parts += "$($activeProfiles.Count) profil(s) VPN actuellement connecte(s)"
    }

    $VPNStatus = [pscustomobject]@{
        HasVpnAdapters        = $hasVpnAdapters
        HasVpnProfiles        = $hasVpnProfiles
        HasActiveVpnProfiles  = $hasActiveVpnProfiles
        Description           = ($parts -join ' | ')
        Adapters              = $adapters
        VpnProfiles           = $vpnProfiles
        ActiveVpnProfiles     = $activeProfiles
    }

    return $VPNStatus
}

