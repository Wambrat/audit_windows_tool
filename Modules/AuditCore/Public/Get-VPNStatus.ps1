function Get-VPNStatus {
    [CmdletBinding()]
    param()

    # Identifier les interfaces de type VPN (approximation via InterfaceDescription/Name)[web:347][web:358][web:356]
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Status -eq 'Up' -and
                    ($_.InterfaceDescription -match 'VPN' -or
                     $_.Name -match 'VPN' -or
                     $_.InterfaceDescription -match 'TAP' -or
                     $_.InterfaceDescription -match 'TUN')
                } |
                Select-Object Name, InterfaceDescription, Status, MacAddress

    $hasVPN = $adapters.Count -gt 0

    $desc = if ($hasVPN) {
        "$($adapters.Count) VPN interface(s) detected"
    } else {
        "0 VPN interface detected"
    }

    [pscustomobject]@{
        HasVPN      = $hasVPN
        Description = $desc
    }
}
