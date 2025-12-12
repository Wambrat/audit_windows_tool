function Get-FirewallAudit {
    [CmdletBinding()]
    param()

    $svc = Get-Service -Name 'mpssvc' -ErrorAction SilentlyContinue

    $svcRunning = $svc -and $svc.Status -eq 'Running'

    $profile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile

    $anyProfileOn = $profile.Enabled -contains $true

    $rdpRules = Get-NetFirewallRule | Where-Object Name -Match "RemoteDesktop" | Where-Object Enabled -eq "True" | Get-NetFirewallAddressFilter | Select-Object Name, LocalAddress, RemoteAddress

    $reco = @()

    if ($rdpRules) {
        $hasAnyAny = $rdpRules | Where-Object { $_.RemoteAddress -eq 'Any' }
        if ($hasAnyAny) {
            $reco += 'RDP rules accept connections from Any: restrict to necessary IPs/subnets.'
        } else {
            $reco += 'RDP rules with filtered RemoteAddress: best practice, check the granularity of sources.'
        }
    } else {
        $reco += 'No RDP rules enabled in the firewall'
    }

    $FA = [pscustomobject]@{
        FirewallStatus   = if ($svc) { $svc.Status } else { 'NotFound' }
        ActiveProfile    = $profile
        RdpRules         = $reco
    }

    Return $FA
}
