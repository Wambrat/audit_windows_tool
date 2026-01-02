function Get-FirewallAudit {
    [CmdletBinding()]
    param()

    # Check Windows Firewall service (mpssvc)
    $svc = Get-Service -Name 'mpssvc' -ErrorAction SilentlyContinue
    $svcRunning = $svc -and $svc.Status -eq 'Running'

    # Get active firewall profile(s)
    $profile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile

    # Check RDP-related firewall rules and their remote scopes
    $rdpRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object Name -Match 'RemoteDesktop' |
        Where-Object Enabled -eq 'True' |
        Get-NetFirewallAddressFilter |
        Select-Object Name, LocalAddress, RemoteAddress

    $rdpReco = @()

    if ($rdpRules) {
        $hasAnyAny = $rdpRules | Where-Object { $_.RemoteAddress -eq 'Any' }
        if ($hasAnyAny) {
            $rdpReco += 'RDP firewall rules allow connections from Any; restrict RemoteAddress to dedicated admin networks or specific IP ranges.'
        }
        else {
            $rdpReco += 'RDP firewall rules are restricted by RemoteAddress; verify that only dedicated admin networks are allowed.'
        }
    }
    else {
        $rdpReco += 'No enabled RDP firewall rules detected; verify if RDP is required and how access is controlled (VPN, jump servers, etc.).'
    }

    # Global firewall recommendation
    $fwReco = @()

    if (-not $svc) {
        $fwReco += 'The Windows Firewall (mpssvc) service is not found; ensure a host-based firewall solution is installed and active.'
    }
    elseif (-not $svcRunning) {
        $fwReco += 'The Windows Firewall service exists but is not running; start it or confirm an alternative firewall product is enforcing filtering.'
    }

    if ($fwReco.Count -eq 0) {
        $fwReco += 'Firewall service appear to be enabled; regularly review inbound rules for unnecessary exposure (RDP, SMB, WinRM, etc.).'
    }

    [pscustomobject]@{
        FirewallServiceStatus = if ($svc) { $svc.Status } else { 'NotFound' }
        FirewallServiceRunning= $svcRunning
        ActiveProfile         = $profile
        RdpRuleDetails        = $rdpRules
        RdpRecommendations    = $rdpReco
        GlobalRecommendations = $fwReco
    }
}
