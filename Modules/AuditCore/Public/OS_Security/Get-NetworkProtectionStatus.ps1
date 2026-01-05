function Get-NetworkProtectionStatus {
    [CmdletBinding()]
    param()

    $mp = Get-MpPreference

    $mode = switch ($mp.EnableNetworkProtection) {
        0     { 'Off' }
        1     { 'Block' }
        2     { 'Audit' }
        $null { 'NotConfigured' }
        default { "Unknown ($($mp.EnableNetworkProtection))" }
    }

    $recommendation = switch ($mp.EnableNetworkProtection) {
        1 {
            "Protection reseau est en mode Blocage ; examinez regulierement les alertes et assurez-vous que les applications metier ne sont pas impactees."
        }
        2 {
            "La Protection reseau est en mode Audit ; examinez les evenements enregistres et prevoyez de passer en mode Blocage sur les points de terminaison critiques."
        }
        0 {
            "La Protection reseau est desactivee ; activez-la d'abord en mode Audit, puis en mode Blocage pour empecher l'acces aux domaines et IPs malveillants."
        }
        $null {
            "La Protection reseau n'est pas configuree ; defini une politique (Audit/Blocage) via GPO, Intune ou Set-MpPreference."
        }
        default {
            "Examinez la configuration actuelle de la Protection reseau et alignez-la sur votre base de renforcement de Defender."
        }
    }

    $NP = [pscustomobject]@{
        EnableNetworkProtection = ($mp.EnableNetworkProtection -ge 1)
        Mode                    = $mode
        RawValue                = $mp.EnableNetworkProtection
        Recommendation          = $recommendation
    }

    return $NP
}

