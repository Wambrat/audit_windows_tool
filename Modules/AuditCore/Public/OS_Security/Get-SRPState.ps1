function Get-SRPState {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    )

    foreach ($path in $paths) {
        $scope = if ($path -like 'HKLM*') { 'Machine' } else { 'User' }

        if (-not (Test-Path $path)) {
            $obj = [pscustomobject]@{
                Scope        = $scope
                RegistryPath = $path
                SRPPresent   = $false
                Comment      = 'Pas de politique de restriction logicielle (SRP) detectee pour cette portee.'
                Recommendation = "Preferez AppLocker ou Windows Defender Application Control (WDAC) plutot que SRP legacy pour le controle des applications."
            }
            [void]$Print.Add($obj)
            continue
        }

        $rulesKey = Join-Path $path '0\Paths'
        $hasRules = Test-Path $rulesKey

        $comment = if ($hasRules) {
            "Des politiques de restriction logicielle (SRP) sont definies pour cette portee."
        } else {
            "La clef racine SRP existe mais aucune regle de chemin n'a ete trouvee."
        }

        $reco = if ($hasRules) {
            "Prevoyez de migrer des SRP legacy vers AppLocker ou WDAC pour un controle des applications plus solide et plus flexible."
        } else {
            "Si SRP n'est pas utilise activement, envisagez de nettoyer les cles legacy et de mettre en oeuvre AppLocker ou WDAC a la place."
        }

        $SRP = [pscustomobject]@{
            Scope          = $scope
            RegistryPath   = $path
            SRPPresent     = $hasRules
            Comment        = $comment
            Recommendation = $reco
        }

        [void]$Print.Add($SRP)
    }

    return $Print
}

