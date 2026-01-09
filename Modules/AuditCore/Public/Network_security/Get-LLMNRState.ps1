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
            LLMNR_Status = 'Active par defaut (aucune politique explicite, la resolution de noms multicast est probablement autorisee)'
            Recommendation = "Aucune politique LLMNR explicite trouvee; configurez EnableMulticast = 0 (Desactiver la resolution de noms multicast) pour desactiver LLMNR."
        }
    }

    if ($llmnrValue -eq 1) {
        $llmnrStatus = 'Active via politique de groupe (la resolution de noms multicast est autorisee)'
        $recommendation = 'LLMNR est explicitement active via la politique de groupe; considerer de le desactiver (EnableMulticast = 0) pour reduire les attaques de spoofing de resolution de noms.'
    } elseif ($llmnrValue -eq 0) {
        $llmnrStatus = 'Desactive via politique de groupe (LLMNR desactive)'
        $recommendation = "LLMNR est desactive via la politique de groupe; ceci est recommande pour reduire les risques de spoofing et d'interception."
    } else {
        $llmnrStatus = "Valeur inconnue ($llmnrValue)"
        $recommendation = "Revoir la configuration LLMNR et l'aligner avec la base de durcissement (typiquement desactive sur les reseaux d'entreprise)."
    }

    return [PSCustomObject]@{
        Value = $llmnrValue
        LLMNR_Status = $llmnrStatus
        Recommendation = $recommendation
    }
}

