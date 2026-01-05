function Get-AppLockerState {
    [CmdletBinding()]
    param()

    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            AppLockerPresent = $false
            AnyRuleEnabled   = $false
            Comment          = 'Aucune strategie AppLocker efficace detectee sur ce systeme.'
            Recommendation   = "Envisagez de deployer une strategie AppLocker (au moins en mode Audit) pour controler l'execution des applications."
        }
    }

    $collections = @('Exe','Script','Msi','Dll','Appx')
    $anyEnabled  = $false

    foreach ($c in $collections) {
        $col = $policy.RuleCollections | Where-Object { $_.CollectionType -eq $c }
        if ($col -and $col.EnforcementMode -eq 'Enabled') {
            $anyEnabled = $true
            break
        }
    }

    [pscustomobject]@{
        AppLockerPresent = $true
        AnyRuleEnabled   = $anyEnabled
        Comment          = if ($anyEnabled) {
                               'AppLocker est present et au moins une collection de regles est en mode applique.'
                           } else {
                               "AppLocker est present mais aucune collection de regles n'est en mode applique."
                           }
        Recommendation   = if ($anyEnabled) {
                               "Examinez regulierement les regles AppLocker pour vous assurer qu'elles couvrent correctement les applications sensibles et qu'elles sont tenues a jour."
                           } else {
                               "Activez d'abord AppLocker en mode Audit, puis basculez progressivement les ensembles de regles requis en mode Applique pour bloquer les applications non autorisees."
                           }
    }
}

