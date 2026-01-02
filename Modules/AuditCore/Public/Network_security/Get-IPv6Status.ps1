function Get-IPv6Status2 {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    # Get IPv6 binding state per network adapter
    $bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled  # True = IPv6 enabled on this interface

    #$allDisabled = $bindings -and ($bindings.Enabled -notcontains $true)

    foreach ($bind in $bindings) {

        $recommendation = if ($bind.Enabled) {
            "IPv6 est activé sur cet adaptateur ; vérifiez qu'IPv6 est correctement routé, filtré et surveillé, ou désactivez-le s'il n'est pas utilisé dans votre environnement."
        } else {
            "IPv6 est désactivé sur cet adaptateur ; cela est généralement sans danger si votre environnement ne dépend pas d'IPv6."
        }

        $ipv6state = [pscustomobject]@{
            Adapter        = $bind.Name
            IPv6Enabled    = $bind.Enabled
            Recommendation = $recommendation
        }

        [void]$Print.Add($ipv6state)
    }

    return $Print
}
