function Get-IPv6Status {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    # Get IPv6 binding state per network adapter
    $bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled  # True = IPv6 enabled on this interface

    $allDisabled = $bindings -and ($bindings.Enabled -notcontains $true)

    foreach ($bind in $bindings) {

        $recommendation = if ($bind.Enabled) {
            'IPv6 is enabled on this adapter; verify that IPv6 is properly routed, filtered and monitored, or disable it if not used in your environment.'
        } else {
            'IPv6 is disabled on this adapter; this is usually safe if your environment does not rely on IPv6.'
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
