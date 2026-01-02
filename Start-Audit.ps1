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

######################################
#       Account Security Audits      #
######################################



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



########## Authentication Level Audit ##########

Write-Host "`n[+] Audit du niveau d'authentification :" -Foregroundcolor Gray
$authLevelAudit = Get-AuthenticationLevelAudit

if ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $true) {
    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est activé via : GPO" -ForegroundColor Green
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est activé via : CSP" -ForegroundColor Green
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas activé." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $false) {
    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [OK] Windows Hello (Consumer/Local) est activé." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) n'est pas activé." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $true) {
    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est activé via : GPO" -ForegroundColor Green
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est activé via : CSP" -ForegroundColor Green
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas activé." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $false) {
    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) est activé. Il est plutôt recommandé de désactiver cette fonctionnalité sur les serveurs." -ForegroundColor Red
    } else {
        Write-Host "   [OK] Windows Hello (Consumer/Local) n'est pas activé." -ForegroundColor Green
    }
} else {
    Write-Host "   [INFORMATION] Le niveau d'authentification n'a pas pu être audité dans ce contexte." -ForegroundColor Yellow
}

########## UAC Audit ##########
Write-Host "`n[+] Audit de la configuration de l'UAC :" -Foregroundcolor Gray
$uacAudit = Get-UACAudit

try {
    if ($uacAudit.UACEnabled -eq 1) {
        Write-Host "   [OK] L'UAC est activé." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] L'UAC est désactivé." -ForegroundColor Red
    }

    if ($uacAudit.FilterAdministratorToken -eq 1) {
        Write-Host "   [OK] Le filtrage du token administrateur est activé." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] Le filtrage du token administrateur est désactivé." -ForegroundColor Red
    }

    if ($uacAudit.LocalAccountTokenFilterPolicy -eq 1) {
        Write-Host "   [OK] La politique de filtrage des tokens pour les comptes locaux est activée." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] La politique de filtrage des tokens pour les comptes locaux est désactivée (risque d'accès non administrateur via le réseau)." -ForegroundColor Red
    }
}
catch {
    Write-Host "Erreur lors de l'affichage des résultats de l'audit UAC"
}



########## JEA Audit ##########

Write-Host "`n[+] Audit de la configuration JEA :" -Foregroundcolor Gray
$JEAAudit = Get-JEAAudit
try {
    if ($JEAAudit.WinRmState -eq 'NotInstalled'){
        Write-Host "   [INFORMATION] WinRM n'est pas installé. JEA ne peut pas être configuré." -ForegroundColor Red
    } elseif ($JEAAudit.WinRmState -eq 'Stopped') {
        Write-Host "   [ALERTE] WinRM est installé mais arrêté. JEA ne peut pas être utilisé tant que WinRM n'est pas démarré." -ForegroundColor Red
    } elseif ($JEAAudit.HasJEASessionConfig -eq $true){
        Write-Host "   [OK] Des endpoints JEA sont configurés sur cette machine." -ForegroundColor Green
        Write-Host "       $($JEAAudit.Recommandation)" -ForegroundColor Gray
    } elseif ($JEAAudit.HasJEASessionConfig -eq $false){
        Write-Host "   [ALERTE] WinRM est fonctionnel mais aucun endpoint JEA n'est configuré." -ForegroundColor Red
    } else {
        Write-Error "   [ERREUR] Impossible d'auditer la configuration JEA." -ForegroundColor Red
    }
} catch {
    Write-Host "Erreur lors de l'affichage des résultats de l'audit JEA"
}



########## Local Groups Audit ##########

Write-Host "`n[+] Audit des groupes locaux :" -Foregroundcolor Gray
$groupsAudit = Get-GroupsAudit

if ($groupsAudit) {
    foreach ($group in $groupsAudit) {
        Write-Host "`nGroupe : $($group.GroupName)" -ForegroundColor Cyan
        if ($group.Members -eq 0) {
            Write-Host "   Aucun membre dans ce groupe." -ForegroundColor Yellow
        } else {
            Write-Host "   Membres : $($group.Members -join ', ')" -ForegroundColor Yellow
            if ($group.MembersCount -gt 1) {
                Write-Host "   [ALERTE] Ce groupe contient un grand nombre de membres ($($group.MembersCount)). Vérifiez qu'il n'y a pas d'utilisateurs non autorisés." -ForegroundColor Red
            } else {
                Write-Host "   [OK] Nombre de membres dans ce groupe : $($group.MembersCount)" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Error "Impossible d'auditer les groupes locaux"
}



########## SMB Shares Audit ##########

Write-Host "`n[+] Audit des partages SMB :" -Foregroundcolor Gray
Get-SMBSharesAudit


######################################
#    Service & Application Audits    #
######################################

########## RDP Audit ##########

Write-Host "`n[+] Audit des services RDP :" -ForegroundColor Gray
$rdpAudit = Get-RDPAudit

if ($rdpAudit -and $rdpAudit.Value) {
    $r = $rdpAudit.Value

    if ($r.RDPEnabled -eq $true) {
        Write-Host "   [ENABLED] RDP est activé sur cette machine." -ForegroundColor Red
    }
    else {
        Write-Host "   [DISABLED] RDP est désactivé au niveau OS." -ForegroundColor Green
    }

    Write-Host "   [RESTRICTED ADMIN] DisableRestrictedAdmin : $($r.DisableRestrictedAdmin)" -ForegroundColor Gray
    Write-Host "   [ENCRYPTION] MinEncryptionLevel : $($r.MinEncryptionLevel)" -ForegroundColor Gray
    Write-Host "   [SECURITY LAYER] SecurityLayer : $($r.SecurityLayer)" -ForegroundColor Gray
    Write-Host "   [NLA] UserAuthentication : $($r.UserAuthentication)" -ForegroundColor Gray

    if ($r.fEncryptRPCTraffic -eq $true) {
        Write-Host "   [RPC] fEncryptRPCTraffic : Enabled" -ForegroundColor Green
    } else {
        Write-Host "   [RPC] fEncryptRPCTraffic : Disabled" -ForegroundColor Red
    }

    if ($r.Recommendation) {
        Write-Host "`n   Recommandation : $($r.Recommendation)" -ForegroundColor Yellow
    }

    if ($rdpAudit.Xml -and $rdpAudit.Xml.Count -gt 0) {
        Write-Host "`n   Actions proposées :" -ForegroundColor Gray
        foreach ($item in $rdpAudit.Xml) {
            Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
        }
    }

} else {
    Write-Error "Impossible d'auditer RDP (Get-RDPAudit n'a pas retourné de résultat)"
}



########## WinRM Audit ##########

Write-Host "`n[+] Audit WinRM :" -ForegroundColor Gray
try {
    $winrmAudit = Get-WinRMAudit

    if (-not $winrmAudit.WinRmEnabled) {
        Write-Host "   [INACTIF] WinRM n'est pas installé ou le service est arrêté." -ForegroundColor Red
        Write-Host "   Recommandation :" -ForegroundColor Yellow
        foreach ($r in $winrmAudit.Recommendations) { Write-Host "      - $r" -ForegroundColor Yellow }
    }
    else {
        Write-Host "   [ACTIF] WinRM est activé." -ForegroundColor Green
        Write-Host "   [TRANSPORT] ListenerTransport : $($winrmAudit.ListenerTransport)" -ForegroundColor Gray
        Write-Host "   [ECOUTE] ListeningOn        : $($winrmAudit.ListeningOn)" -ForegroundColor Gray
        Write-Host "   [FILTRES IP] IPv4 : $($winrmAudit.IPv4Filter)    IPv6 : $($winrmAudit.IPv6Filter)" -ForegroundColor Gray

        if ($winrmAudit.ServiceAuth) {
            Write-Host "   [AUTH SERVICE] Basic : $($winrmAudit.ServiceAuth.Basic)    Unencrypted : $($winrmAudit.ServiceAuth.Unencrypted)" -ForegroundColor Gray
        }
        if ($winrmAudit.ClientAuth) {
            Write-Host "   [AUTH CLIENT]  Basic : $($winrmAudit.ClientAuth.Basic)" -ForegroundColor Gray
        }

        if ($winrmAudit.RmUsersNotAdmins -and $winrmAudit.RmUsersNotAdmins.Count -gt 0) {
            Write-Host "   [USERS] Comptes dans Remote Management Users (non-admin) : $($winrmAudit.RmUsersNotAdmins -join ', ')" -ForegroundColor Yellow
        }

        if ($winrmAudit.Recommendations -and $winrmAudit.Recommendations.Count -gt 0) {
            Write-Host "`n   Recommandations :" -ForegroundColor Yellow
            foreach ($rec in $winrmAudit.Recommendations) {
                Write-Host "      - $rec" -ForegroundColor Yellow
            }
        } else {
            Write-Host "   [OK] Configuration WinRM conforme aux bonnes pratiques détectée." -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Get-WinRMAudit a échoué : $($_.Exception.Message)"
}



########## SMB Audit ##########

Write-Host "`n[+] Audit SMB :" -ForegroundColor Gray

try {
    $smbAudit = Get-SMBAudit

    if ($smbAudit -and $smbAudit.Value) {
        $s = $smbAudit.Value

        # Affichage du statut SMBv1
        if ($s.SMBv1State -eq $true) {
            Write-Host "   [SMBv1] [ALERTE] SMBv1 est activé. Il est recommandé de le désactiver." -ForegroundColor Red
        } else {
            Write-Host "   [SMBv1] [OK] SMBv1 est désactivé." -ForegroundColor Green
        }

        # Affichage du statut SMBv2/3
        if ($s.SMBv2State -eq $true) {
            Write-Host "   [SMBv2/3] [OK] SMBv2/3 est activé." -ForegroundColor Green
        } else {
            Write-Host "   [SMBv2/3] [ALERTE] SMBv2/3 est désactivé." -ForegroundColor Red
        }

        # Affichage du statut de la signature SMB
        if ($s.RequireSecuritySignature -eq $true) {
            Write-Host "   [SIGNING] [OK] La signature de sécurité SMB est requise." -ForegroundColor Green
        } else {
            Write-Host "   [SIGNING] [ALERTE] La signature de sécurité SMB n'est pas requise." -ForegroundColor Red
        }

        if ($s.Comment) {
            Write-Host "`n   Détails : $($s.Comment)" -ForegroundColor Gray
        }

        if ($s.Recommendation) {
            Write-Host "`n   Recommandation : $($s.Recommendation)" -ForegroundColor Yellow
        }

        # Affichage des actions proposées
        if ($smbAudit.Xml -and $smbAudit.Xml.Count -gt 0) {
            Write-Host "`n   Actions proposées :" -ForegroundColor Gray
            foreach ($item in $smbAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Error "Impossible d'auditer SMB (Get-SMBAudit n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-SMBAudit a échoué : $($_.Exception.Message)"
}


########### Update Audit ##########

Write-Host "`n[+] Audit des mises à jour et version OS :" -ForegroundColor Gray
try {
    $osInfo = Get-OSVersionInfo
    if ($osInfo) {
        Write-Host "`n[OS] $($osInfo.Caption) - Version $($osInfo.Version) (Full: $($osInfo.FullVersion))" -ForegroundColor Cyan
        if ($osInfo.InstallDate) {
            $installDate = [datetime]$osInfo.InstallDate
            Write-Host "Build: $($osInfo.BuildNumber)   Installé le: $($installDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
        } else {
            Write-Host "Build: $($osInfo.BuildNumber)   InstallDate: Non disponible" -ForegroundColor Gray
        }
    }

    $updateSource = Get-UpdateSource
    Write-Host "`n[Source de mises à jour] $updateSource" -ForegroundColor Gray

    $kbList = Get-InstalledKB
    if ($kbList -and $kbList.Count -gt 0) {
        Write-Host "`n[+] Dernières mises à jour installées (10 dernières) :" -ForegroundColor Gray
        $kbList | Select-Object -First 10 | Format-Table HotFixID, Description, @{Name='InstalledOn';Expression={ ($_ .InstalledOn -as [datetime]).ToString('yyyy-MM-dd') }}, InstalledBy -AutoSize
    } else {
        Write-Host "Aucune mise à jour détectée via Get-HotFix" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Erreur lors de la collecte des informations de mise à jour : $($_.Exception.Message)"
}


######################################
#      Network Security Audits       #
######################################

########## IPv6 Audit ##########
Write-Host "`n[+] Audit de la configuration IPv6 :" -ForegroundColor Gray
$ipv6Audit = Get-IPv6Status

if ($ipv6Audit -and $ipv6Audit.Count -gt 0) {
    foreach ($adapter in $ipv6Audit) {
        if ($adapter.IPv6Enabled -eq $true) {
            Write-Host "   [ENABLED] Adapter: $($adapter.Adapter) - IPv6 is enabled." -ForegroundColor Red
            Write-Host "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [DISABLED] Adapter: $($adapter.Adapter) - IPv6 is disabled." -ForegroundColor Green
            Write-Host "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Error "Impossible d'auditer la configuration IPv6 (Get-IPv6Status n'a pas retourné de résultat)"
}


# --- Fin ---
Write-Host "`nAudit terminé." -ForegroundColor Cyan

