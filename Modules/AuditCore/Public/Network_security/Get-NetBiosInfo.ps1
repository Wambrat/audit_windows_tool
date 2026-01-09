function Get-NetBiosInfo {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    # Get only IP-enabled adapters
    $netAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration |
                   Where-Object { $_.IPEnabled -eq $true }

    foreach ($adapter in $netAdapters) {

        $netbiosStatus = switch ($adapter.TcpipNetbiosOptions) {
            0 { 'Default (typically enabled unless disabled by DHCP/server policy)' }
            1 { 'Enabled' }
            2 { 'Disabled' }
            default { 'Unknown' }
        }

        $recommendation = switch ($adapter.TcpipNetbiosOptions) {
            2 {
                "NetBIOS sur TCP/IP est desactive sur cet interface ; ceci est recommande sur les reseaux modernes utilisant uniquement DNS."
            }
            1 {
                "NetBIOS sur TCP/IP est active ; considerer de le desactiver (TcpipNetbiosOptions = 2) pour reduire la resolution de noms hereditee et la surface d attaque."
            }
            0 {
                "NetBIOS sur TCP/IP suit la configuration par defaut/DHCP; explicitement definir TcpipNetbiosOptions = 2 pour desactiver NetBIOS sur TCP/IP si possible."
            }
            default {
                "Revoir la configuration de NetBIOS sur TCP/IP pour cet interface et l'aligner avec votre base de durcissement (generalement desactive)."
            }
        }

        $Netbios = [PSCustomObject]@{
            Interface       = $adapter.Description
            NetBIOS_Status  = $netbiosStatus
            TcpipNetbiosOptions = $adapter.TcpipNetbiosOptions
            Recommendation  = $recommendation
        }

        [void]$Print.Add($Netbios)
    }

    return $Print
}

