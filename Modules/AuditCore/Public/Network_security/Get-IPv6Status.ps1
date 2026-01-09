function Get-IPv6Status {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    # Get IPv6 binding state per network adapter
    $bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled  # True = IPv6 enabled on this interface

    #$allDisabled = $bindings -and ($bindings.Enabled -notcontains $true)

    foreach ($bind in $bindings) {

        $recommendation = if ($bind.Enabled) {
            "IPv6 est active sur cet adaptateur ; verifiez qu'IPv6 est correctement route, filtre et surveille, ou desactivez-le s'il n'est pas utilise dans votre environnement."
        } else {
            "IPv6 est desactive sur cet adaptateur ; cela est generalement sans danger si votre environnement ne depend pas d'IPv6."
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

