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

########## Local User Audit ##########

$localUserAudit = Get-LocalUserAudit

if ($localUserAudit) {
    Write-Host "`n[+] Compte locaux identifiés :" -ForegroundColor Gray
    
    if (($localUserAudit.AdminAccountSID -match "-500$") -and ($localUserAudit.AdminEnabled -eq $true)){
        Write-Host "`nLe compte Administrateur par défaut est activé" -ForegroundColor Red
        Write-Host $localUserAudit.AdminRecommandation.Enabled -ForegroundColor Yellow     
    }
    else {
        Write-Host $localUserAudit.AdminRecommandation.Disabled -ForegroundColor Green
    }

    if (($localUserAudit.GuestAccountSID -match "-501$") -and ($localUserAudit.GuestEnabled -eq $true)){
        Write-Host "`nLe compte Invité par défaut est activé" -ForegroundColor Red
        Write-Host $localUserAudit.GuestRecommandation.Enabled -ForegroundColor Yellow
    } else {
        Write-Host $localUserAudit.GuestRecommandation.Disabled -ForegroundColor Green
    }
}
else {
    Write-Error "Impossible d'auditer les utilisateurs locaux"
}

########## LAPS Audit ##########

$lapsAudit = Get-LAPSAudit
Write-Host "`n[+] Audit de la configuration LAPS :" -Foregroundcolor Gray

if ($lapsaudit){

    if ($context.Domainjoined -eq $true) {

        # Affichage dynamique selon le résultat
        switch ($lapsAudit.Status) {
            "PASS" {
                Write-Host "   [OK] $($lapsAudit.DetectedMethods)" -ForegroundColor Green
                # Si on a un warning mineur (ex: Legacy + Modern en même temps)
                if ($lapsAudit.Recommendation -match "ATTENTION") {
                    Write-Host "   $($lapsAudit.Recommendation)" -ForegroundColor Magenta
                }
            }
            "WARNING" {
                # Cas spécifique Legacy seul
                Write-Host "   [OBSOLETE] $($lapsAudit.DetectedMethods)" -ForegroundColor Orange
                Write-Host "   -> $($lapsAudit.Recommendation)" -ForegroundColor Yellow
            }
            "FAIL" {
                Write-Host "   [ALERTE] $($lapsAudit.Recommendation)" -ForegroundColor Red
            }
        }

    }
    else {
        Write-Host "`rLa machine n'est pas jointe à un domaine. LAPS n'est pas auditable" -ForegroundColor Magenta
    }
}

########## Active Directory Password Policy Audit ##########

if ($context.Domainjoined -eq $true){
    $adPasswordPolicy = Get-ADPolPassAudit

    if ($adPasswordPolicy -and $context.Domainjoined -eq $true) {

        Write-Host "`n[+] Audit des politiques de mots de passe Active Directory :" -Foregroundcolor Gray
        try {
            # Affichage Longueur
            if ($adPasswordPolicy.MinLengthStatus -eq "FAIL") {
                Write-Host "   [LONGUEUR]   [ALERTE] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Red
            } else {
                Write-Host "   [LONGUEUR]   [OK] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Green
            }

            # Affichage Complexité
            if ($adPasswordPolicy.ComplexityStatus -eq "FAIL") {
                Write-Host "   [COMPLEXITE] [ALERTE] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Red
            } else {
                Write-Host "   [COMPLEXITE] [OK] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Green
            }

            # Affichage Verrouillage
            if ($adPasswordPolicy.LockoutStatus -eq "FAIL") {
                Write-Host "   [BLOCAGE]    [ALERTE] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Red
            } elseif ($adPasswordPolicy.LockoutStatus -eq "WARNING") {
                Write-Host "   [BLOCAGE]    [MOYEN] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Magenta
            } else {
                Write-Host "   [BLOCAGE]    [OK] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Erreur lors de l'affichage des résultats de l'audit de la politique de mot de passe AD"
        }
    }
} else {
########## Local Password Policy Audit ##########

    Write-Host "`n[+] Audit des politiques de mots de passe :" -Foregroundcolor Gray
    $passwordPolicy = Get-PolPassAudit

    if ($passwordPolicy){
        try {
            # Affichage Longueur
            if ($passwordPolicy.MinLengthStatus -eq "FAIL") {
                Write-Host "   [LONGUEUR]   [ALERTE] $($passwordPolicy.MinLengthReco)" -ForegroundColor Red
            } else {
                Write-Host "   [LONGUEUR]   [OK] $($passwordPolicy.MinLengthReco)" -ForegroundColor Green
            }

            # Affichage Complexité
            if ($passwordPolicy.ComplexityStatus -eq "FAIL") {
                Write-Host "   [COMPLEXITE] [ALERTE] $($passwordPolicy.ComplexityReco)" -ForegroundColor Red
            } else {
                Write-Host "   [COMPLEXITE] [OK] $($passwordPolicy.ComplexityReco)" -ForegroundColor Green
            }

            # Affichage Verrouillage
            if ($passwordPolicy.LockoutStatus -eq "FAIL") {
                Write-Host "   [BLOCAGE]    [ALERTE] $($passwordPolicy.LockoutReco)" -ForegroundColor Red
            } elseif ($passwordPolicy.LockoutStatus -eq "WARNING") {
                Write-Host "   [BLOCAGE]    [MOYEN] $($passwordPolicy.LockoutReco)" -ForegroundColor Magenta
            } else {
                Write-Host "   [BLOCAGE]    [OK] $($passwordPolicy.LockoutReco)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Erreur lors de l'affichage des résultats de l'audit de la politique de mot de passe"
        }
    }
}


# Start-Sleep -Seconds 30
# --- Fin ---
Write-Host "`nAudit terminé." -ForegroundColor Cyan

