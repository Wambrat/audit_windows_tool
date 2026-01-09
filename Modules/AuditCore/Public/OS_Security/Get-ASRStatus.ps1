function Get-ASRStatus {
    [CmdletBinding()]
    param()

    $results = [System.Collections.ArrayList]@()


    $mp = Get-MpPreference

    $ids     = $mp.AttackSurfaceReductionRules_Ids
    $actions = $mp.AttackSurfaceReductionRules_Actions

    if (-not $ids) {
        return [pscustomobject]@{
            RuleId        = $null
            Action        = $null
            Enabled       = $false
            Comment       = "Aucune regle ASR n'est actuellement configuree (ASR desactivee)."
            Recommendation = "Activez les regles de reduction de la surface d'attaque de Microsoft Defender, telles que : 
                - Bloquer les macros malveillantes dans Office.
                - Empecher l'execution de scripts suspects (PowerShell, JavaScript, etc.).
                - Blocage des processus non autorises provenant d'emplacements sensibles (par exemple, %AppData% ou %Temp%).
                - Protection contre les pieces jointes malveillantes dans les emails."
        }
    }

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $rawAction = $actions[$i]

        $mode = switch ($rawAction) {
            0 { 'Desactive' }
            1 { 'Bloque' }
            2 { 'Audit' }
            6 { 'Avertir' }
            default { "Inconnu ($rawAction)" }
        }

        # Simple recommendation based on mode
        $recommendation = switch ($rawAction) {
            0 { "Envisagez au moins d'activer cette regle ASR en mode Audit, puis de passer en mode 'Bloque' apres validation." }
            2 { "Examinez les journaux d'audit de cette regle ASR et prevoyez de la deplacer vers le mede 'Bloque' lorsqu'elle est stable." }
            6 { "Surveillez l'experience utilisateur pour cette regle ASR et envisagez de passer en mode 'Bloque' sur les machines renforces." }
            1 { "Assurez-vous que cette regle ASR en mode Bloc a ete validee dans votre environnement et qu'elle est documentee." }
            default { 'Veuillez verifier cette configuration de regle ASR par rapport aux directives de renforcement de la securite de Microsoft et aux directives internes.' }
        }

        $ASR = [pscustomobject]@{
            RuleId         = $ids[$i]
            Action         = $mode
            Enabled        = ($rawAction -eq 1)
            Comment        = "La regle ASR est actuellement configuree pour '$mode'."
            Recommendation = $recommendation
        }

        [void]$results.Add($ASR)
    }

    return $results
}

