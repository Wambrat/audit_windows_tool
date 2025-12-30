# Récupère le chemin du dossier où se trouve ce fichier .psm1
$publicFunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath "Public"

# Charge tous les fichiers .ps1 situés dans le dossier Public
Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" -Recurse -File | ForEach-Object {
    try {
        . $_.FullName
        Write-Verbose "Fonction chargée : $($_.BaseName)"
    }
    catch {
        Write-Error "Impossible de charger la fonction $($_.BaseName) : $_"
    }
}

# Exporte toutes les fonctions chargées pour qu'elles soient visibles par le script principal
Export-ModuleMember -Function *