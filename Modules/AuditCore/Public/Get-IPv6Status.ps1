function Get-IPv6Status {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled  # True = IPv6 actif sur l’interface[web:341][web:343][web:344]

    $allDisabled = $bindings -and ($bindings.Enabled -notcontains $true)

    foreach($bind in $bindings){
        
        $ipv6state = [pscustomobject]@{

            Adapters = $bind.Name
            Ipv6Enabled = $bind.Enabled

        }

        [void]$Print.Add($ipv6state)

    }

    Return $Print

}
