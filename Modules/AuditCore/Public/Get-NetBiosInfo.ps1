function Get-NetBiosInfo {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $netAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

    foreach ($adapter in $netAdapters) {
        $netbios = switch ($adapter.TcpipNetbiosOptions) {
            0 { "Default (usually Enabled unless DHCP server disables it)" }
            1 { "Enabled" }
            2 { "Disabled" }
            default { "Unknown" }
        }

        $Netbios = [PSCustomObject]@{
            Interface      = $adapter.Description
            NetBIOS_Status = $netbios
        }

        [void]$Print.Add($NetBios)

    }

    Return $Print

}
