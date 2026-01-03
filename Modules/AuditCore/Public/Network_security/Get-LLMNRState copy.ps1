function Get-LLMNRState {
    [CmdletBinding()]
    param()

    $llmnrRegPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
    $llmnrKey = 'EnableMulticast'

    $llmnrValue = Get-ItemProperty -Path $llmnrRegPath -Name $llmnrKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $llmnrKey

    if (-not $llmnrValue) {
        $llmnrValue = $null
        return [PSCustomObject]@{
            Value = $llmnrValue
            LLMNR_Status = 'Activé par défaut (aucune politique explicite, la résolution de noms multicast est probablement autorisée)'
            Recommendation = "Aucune politique LLMNR explicite trouvée; configurez EnableMulticast = 0 (Désactiver la résolution de noms multicast) pour désactiver LLMNR."
        }
    }

    if ($llmnrValue -eq 1) {
        $llmnrStatus = 'Activé via politique de groupe (la résolution de noms multicast est autorisée)'
        $recommendation = 'LLMNR est explicitement activé via la politique de groupe; considérer de le désactiver (EnableMulticast = 0) pour réduire les attaques de spoofing de résolution de noms.'
    } elseif ($llmnrValue -eq 0) {
        $llmnrStatus = 'Désactivé via politique de groupe (LLMNR désactivé)'
        $recommendation = "LLMNR est désactivé via la politique de groupe; ceci est recommandé pour réduire les risques de spoofing et d'interception."
    } else {
        $llmnrStatus = "Valeur inconnue ($llmnrValue)"
        $recommendation = "Revoir la configuration LLMNR et l'aligner avec la base de durcissement (typiquement désactivé sur les réseaux d'entreprise)."
    }

    return [PSCustomObject]@{
        Value = $llmnrValue
        LLMNR_Status = $llmnrStatus
        Recommendation = $recommendation
    }
}
