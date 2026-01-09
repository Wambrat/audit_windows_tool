function Get-DeviceGuardStatus {
    [CmdletBinding()]
    param()

    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
                          -Namespace root\Microsoft\Windows\DeviceGuard `
                          -ErrorAction SilentlyContinue

    if (-not $dg) {
        return [pscustomobject]@{
            VirtualizationBasedSecurityStatus             = $null
            UserModeCodeIntegrityPolicyEnforcementStatus  = $null
            CodeIntegrityPolicyEnforcementStatus          = $null
            SecurityServicesConfigured                    = $null
            SecurityServicesRunning                       = $null
            WDAC_Active                                   = $false
            VBS_Active                                    = $false
            Comment                                       = "L'etat Device Guard/VBS n'a pas pu être recupere (Win32_DeviceGuard non disponible)."
            Recommendation                                = "Verifiez la version du système d'exploitation et que Device Guard /VBS est pris en charge et correctement configure sur ce système."
        }
    }

    # VBS status: 2 = enabled, 0/1 = disabled or not running
    $vbsActive  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
    # WDAC (User Mode Code Integrity): 2 = enforced
    $wdacActive = ($dg.UserModeCodeIntegrityPolicyEnforcementStatus -eq 2)

    $cicActive = switch ($dg.CodeIntegrityPolicyEnforcementStatus) {
        0 { 'Desactive' }
        1 { 'Mode audit' }
        2 { 'Applique' }
        Default { "Valeur inconnue ($($dg.CodeIntegrityPolicyEnforcementStatus))" }
    }

    # Build a short comment + recommendation
    $comment = "VBS status: $($dg.VirtualizationBasedSecurityStatus); UMCI (WDAC) status: $($dg.UserModeCodeIntegrityPolicyEnforcementStatus); CI: $cicActive."
    $recommendation = if (-not $vbsActive -and -not $wdacActive) {
        "Envisagez d'activer la securite basee sur la virtualisation (VBS) et le controle des applications Windows Defender (WDAC) sur les systèmes critique pour renforcer le noyau et controler l'execution du code."
    }
    elseif ($vbsActive -and -not $wdacActive) {
        "VBS est active. evaluez et deployez les politiques d'integrite du code WDAC (au moins en mode Audit) pour controler quels binaires et scripts peuvent s'executer."
    }
    elseif ($wdacActive -and $cicActive -eq 'Audit mode') {
        "WDAC /Integrite du code est en mode Audit. Examinez les journaux d'audit et prevoyez de deplacer les systèmes critiques en mode applique une fois stables."
    }
    elseif ($wdacActive -and $cicActive -eq 'Enforced') {
        "WDAC /Integrite du code est applique. Examinez et mettez à jour regulièrement les politiques pour garantir que seul le code fiable est autorise tout en minimisant l'impact operationnel."
    }
    else {
        "Examinez la configuration actuelle de Device Guard/VBS et alignez-la sur votre base de reference de renforcement pour les points de terminaison et les serveurs critiques."
    }

    [pscustomobject]@{
        VirtualizationBasedSecurityStatus             = $dg.VirtualizationBasedSecurityStatus
        UserModeCodeIntegrityPolicyEnforcementStatus  = $dg.UserModeCodeIntegrityPolicyEnforcementStatus
        CodeIntegrityPolicyEnforcementStatus          = $cicActive
        SecurityServicesConfigured                    = $dg.SecurityServicesConfigured
        SecurityServicesRunning                       = $dg.SecurityServicesRunning
        WDAC_Active                                   = $wdacActive
        VBS_Active                                    = $vbsActive
        Comment                                       = $comment
        Recommendation                                = $recommendation
    }
}

