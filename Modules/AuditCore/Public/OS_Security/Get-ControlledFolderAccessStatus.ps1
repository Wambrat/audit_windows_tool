function Get-ControlledFolderAccessStatus {
    [CmdletBinding()]
    param()

    # Get current Microsoft Defender Controlled Folder Access configuration
    $mp = Get-MpPreference

    $mode = switch ($mp.EnableControlledFolderAccess) {
        0 { 'Desactive' }
        1 { 'Bloquer' }
        2 { 'Verification' }
        3 { 'Bloquer la modification du disque uniquement' }
        4 { 'Auditer uniquement la modification du disque' }
        $null { 'Non Configure' }
        default { "Inconnu ($($mp.EnableControlledFolderAccess))" }
    }

    # Simple recommendation based on current mode
    $recommendation = switch ($mp.EnableControlledFolderAccess) {
        0       {"Envisagez d'abord d'activer l'acces contrôle aux dossiers en mode Audit pour evaluer l'impact, puis passez à 'Bloquer' pour les points de terminaison critiques."}
        2       {"Examinez les evenements d'audit pour l'acces contrôle aux dossiers et prevoyez de passer en mode Blocage sur les points de terminaison de grande valeur une fois que le bruit sera acceptable."}
        1       {"Assurez-vous que la liste des dossiers proteges et des applications autorisees est regulierement revue pour equilibrer la securite et la convivialite."}
        3       {"Verifiez que la protection du disque uniquement est suffisante; envisagez le mode 'Bloquer' complet pour les systemes tres sensibles."}
        4       {"Utilisez les donnees d'audit sur les modifications de disque pour decider où des politiques de blocage plus strictes sont requises."}
        default {"Examinez la configuration de l'acces contrôle aux dossiers de Defender et alignez-la sur votre strategie de protection contre les ransomwares."}
    }

    $CFA = [pscustomobject]@{
        EnableControlledFolderAccess = $mp.EnableControlledFolderAccess
        Mode                         = $mode
        Recommendation               = $recommendation
    }

    return $CFA
}

