# Recupere le chemin du dossier ou se trouve ce fichier .psm1
$publicFunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath "Public"

# Charge tous les fichiers .ps1 situes dans le dossier Public
Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" -Recurse -File | ForEach-Object {
    try {
        . $_.FullName
        Write-Verbose "Fonction chargee : $($_.BaseName)"
    }
    catch {
        Write-Error "Impossible de charger la fonction $($_.BaseName) : $_"
    }
}

# Exporte toutes les fonctions chargees pour qu'elles soient visibles par le script principal
Export-ModuleMember -Function *