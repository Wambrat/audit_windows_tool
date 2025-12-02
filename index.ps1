# Import common_functions early so logging helpers are available
$ModulePath = ".\common_functions\common_functions.psm1"
try {
    Import-Module $ModulePath -ErrorAction Stop
} catch {
    Write-Warning "Le module common_functions n'a pas pu être importé: $_"
    exit 1
}

