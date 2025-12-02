# --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptPath = $PSScriptRoot
$ModulePath = Join-Path -Path $ScriptPath -ChildPath "Modules\AuditCore"

# --- Importation du Module ---
Write-Host "Chargement du module d'audit..." -ForegroundColor Cyan
if (Test-Path $ModulePath) {
    Import-Module -Name $ModulePath -Force
}
else {
    Write-Error "Le module AuditCore est introuvable dans $ModulePath"
    exit
}

# --- Exécution de l'Audit ---
Write-Host "Démarrage de l'audit sur $env:COMPUTERNAME..." -ForegroundColor Green

# 1. Récupération du contexte (appel de notre fonction importée)
$context = Get-HostContext

if ($context) {
    Write-Host "`n[+] Contexte Identifié :" -ForegroundColor Yellow
    $context | Format-List
    
    # Logique conditionnelle basé sur le contexte
    if ($context.OSRole -eq "Server") {
        Write-Host ">> Mode Audit Serveur activé." -ForegroundColor Gray
    }
    elseif ($context.HardwareType -eq "Virtual Machine") {
        Write-Host ">> Machine Virtuelle détectée : Vérification des Integration Tools requise." -ForegroundColor Gray
    }
}
else {
    Write-Error "Impossible de déterminer le contexte de la machine."
}


$localUserAudit = Get-LocalUserAudit

if ($localUserAudit) {
    Write-Host "`n[+] Compte locaux identifiés :" -ForegroundColor Yellow
    
    if (($localUserAudit.AdminAccountSID -match "-500$") -and ($localUserAudit.AdminEnabled -eq $false)){
        Write-Host "`n Le compte Administrateur par défaut est activé" -ForegroundColor Red
        Write-Host $localUserAudit.AdminRecommandation.Enabled -ForegroundColor Yellow     
    }
}


# --- Fin ---
Write-Host "`nAudit terminé." -ForegroundColor Cyan