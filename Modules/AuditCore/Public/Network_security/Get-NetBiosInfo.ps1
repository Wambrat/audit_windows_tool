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
                'NetBIOS over TCP/IP is disabled on this interface; this is recommended on modern networks using DNS only.'
            }
            1 {
                'NetBIOS over TCP/IP is enabled; consider disabling it (TcpipNetbiosOptions = 2) to reduce legacy name resolution and attack surface.'
            }
            0 {
                'NetBIOS state follows default/DHCP configuration; explicitly set TcpipNetbiosOptions = 2 to disable NetBIOS over TCP/IP where possible.'
            }
            default {
                'Review NetBIOS over TCP/IP configuration for this interface and align with your hardening baseline (usually disabled).'
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
