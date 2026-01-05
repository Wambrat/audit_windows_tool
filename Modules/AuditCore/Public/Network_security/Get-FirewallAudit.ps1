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
            $rdpReco += "Les regles de pare-feu RDP autorisent les connexions depuis Any ; restreignez RemoteAddress aux reseaux d'administration dedies ou aux plages IP specifiques."
        }
        else {
            $rdpReco += "Les regles de pare-feu RDP sont restreintes par RemoteAddress ; verifiez que seuls les reseaux d'administration dedies sont autorises."
        }
    }
    else {
        $rdpReco += "Aucune regle de pare-feu RDP active detectee ; verifiez si RDP est requis et comment l acces est controle (VPN, serveurs de saut, etc.)."
    }

    # Global firewall recommendation
    $fwReco = @()

    if (-not $svc) {
        $fwReco += "Le service Windows Firewall (mpssvc) est introuvable ; assurez-vous qu'une solution de pare-feu au niveau de l'hote est installee et active."
    }
    elseif (-not $svcRunning) {
        $fwReco += "Le service Windows Firewall existe mais n'est pas en cours d'execution ; demarrez-le ou confirmez qu'un produit de pare-feu alternatif applique le filtrage."
    }

    if ($fwReco.Count -eq 0) {
        $fwReco += 'Le service de pare-feu Windows semble etre actif; examinez regulierement les regles d entrance pour eviter l exposition inutile (RDP, SMB, WinRM, etc.).'
    }

    return [pscustomobject]@{
        FirewallServiceStatus = if ($svc) { $svc.Status } else { 'NotFound' }
        FirewallServiceRunning= $svcRunning
        ActiveProfile         = $profile
        RdpRuleDetails        = $rdpRules
        RdpRecommendations    = $rdpReco
        GlobalRecommendations = $fwReco
    }
}

