function Get-WinRMAudit {
    [CmdletBinding()]
    param()

    $winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue

    if (-not $winrmSvc -or $winrmSvc.Status -eq 'Stopped') {
        return [pscustomobject]@{
            WinRmEnabled       = $false
            ListenerTransport  = $null
            ListeningOn        = $null
            IPv4Filter         = $null
            IPv6Filter         = $null
            ServiceAuth        = $null
            ClientAuth         = $null
            RmUsersNotAdmins   = $null
            Recommendations    = @(
                'WinRM service is stopped or not installed. If remote management is required, enable and configure it securely (HTTPS listener, restricted IP filters, hardened authentication).'
            )
        }
    }

    [xml]$listenersXml = winrm enumerate winrm/config/listener -format:xml 2>$null
    [xml]$serviceXml   = winrm get winrm/config/service   -format:xml 2>$null
    [xml]$clientXml    = winrm get winrm/config/client    -format:xml 2>$null

    $remoteMgmtUsers = Get-LocalGroupMember -SID 'S-1-5-32-580' -ErrorAction SilentlyContinue
    $adminUsers      = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue

    $rmOnly = @()
    if ($remoteMgmtUsers) {
        $rmOnly = $remoteMgmtUsers | Where-Object {
            $name = $_.Name
            -not ($adminUsers.Name -contains $name)
        }
    }

    $listener      = $listenersXml.ChildNodes.Listener
    $transport     = $listener.Transport
    $listeningOn   = $listener.ListeningOn
    $ipv4Filter    = $serviceXml.Service.IPv4Filter
    $ipv6Filter    = $serviceXml.Service.IPv6Filter
    $serviceAuth   = $serviceXml.Service.Auth
    $clientAuth    = $clientXml.Client.Auth
    $rmNotAdmins   = $rmOnly.Name

    $reco = @()

    # 1. Transport / chiffrement
    if ($transport -contains 'HTTP' -and -not ($transport -contains 'HTTPS')) {
        $reco += 'Configure an HTTPS WinRM listener and disable HTTP listeners to avoid unencrypted management traffic.'
    }

    # 2. Filtres IP trop larges
    if ($ipv4Filter -eq '*' -or [string]::IsNullOrWhiteSpace($ipv4Filter)) {
        $reco += 'Restrict WinRM IPv4Filter to specific management subnets instead of allowing all (*) to reduce exposure.'
    }
    if ($ipv6Filter -eq '*' -or [string]::IsNullOrWhiteSpace($ipv6Filter)) {
        $reco += 'Restrict WinRM IPv6Filter to specific management subnets instead of allowing all (*) to reduce exposure.'
    }

    # 3. Authentification côté service
    if ($serviceAuth.Basic -eq 'true') {
        $reco += 'Avoid using Basic authentication for WinRM, or ensure it is only allowed over HTTPS with strong credential policies.'
    }
    if ($serviceAuth.Unencrypted -eq 'true') {
        $reco += 'Disable unencrypted WinRM traffic (Service.Auth.Unencrypted = false) to enforce encryption for all remote management.'
    }

    # 4. Authentification côté client
    if ($clientAuth.Basic -eq 'true') {
        $reco += 'Harden WinRM client settings to avoid Basic authentication where possible, preferring Kerberos/Negotiate.'
    }

    # 5. Groupe Remote Management Users
    if ($rmNotAdmins -and $rmNotAdmins.Count -gt 0) {
        $reco += 'Review non-administrator accounts in the "Remote Management Users" group and ensure their permissions are justified and aligned with least privilege.'
    }

    if (-not $reco) {
        $reco += 'WinRM appears configured with encrypted transport and restricted filters; validate settings against your hardening baseline and remote management requirements.'
    }

    $Output = [pscustomobject]@{
        WinRmEnabled      = $true
        ListenerTransport = $transport
        ListeningOn       = $listeningOn
        IPv4Filter        = $ipv4Filter
        IPv6Filter        = $ipv6Filter
        ServiceAuth       = $serviceAuth
        ClientAuth        = $clientAuth
        RmUsersNotAdmins  = $rmNotAdmins
        Recommendations   = $reco
    }

    Return $Output
}
