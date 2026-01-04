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
        Write-Host "   [INACTIF] WinRM n'est pas installé ou le service est arrêté." -ForegroundColor Purple
        Write-Host "   Recommandation :" -ForegroundColor Yellow
        foreach ($r in $winrmAudit.Recommendations) { Write-Host "      - $r" -ForegroundColor Yellow }
    }
    else {
        Write-Host "   [ACTIF] WinRM est activé." -ForegroundColor Yellow
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
        $kbList | Select-Object -First 10 | Format-Table HotFixID, Description, @{Name='InstalledOn';Expression={ ($_.InstalledOn -as [datetime]).ToString('yyyy-MM-dd') }}, InstalledBy -AutoSize
    } else {
        Write-Host "Aucune mise à jour détectée via Get-HotFix" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Erreur lors de la collecte des informations de mise à jour : $($_.Exception.Message)"
}

########## Installed Applications Audit ##########

Write-Host "`n[+] Audit des applications installées :" -ForegroundColor Gray
try {
    $apps = Get-InstalledApplications

    if ($apps -and $apps.Count -gt 0) {
        Write-Host "   [INFO] Nombre d'applications détectées : $($apps.Count)" -ForegroundColor Gray
        $apps | Select-Object Name, Version, Publisher, InstallLocation |
            Sort-Object Name |
            Format-Table -AutoSize
    } else {
        Write-Host "   [INFO] Aucune application installée détectée." -ForegroundColor Yellow
    }

    # Vérification des mises à jour applicatives via WinGet (si disponible)
    $appUpgrades = Get-AppUpgrade -ErrorAction SilentlyContinue
    if ($appUpgrades -and $appUpgrades.Count -gt 0) {
        Write-Host "`n   [Mises à jour disponibles via WinGet] :" -ForegroundColor Yellow
        $appUpgrades |
            Select-Object Name, InstalledVersion, @{Name='Available';Expression={$_.AvailableVersions -join ','}} |
            Format-Table -AutoSize
        Write-Host "   Recommandation : utiliser `winget upgrade --all` pour mettre à jour les applications prises en charge." -ForegroundColor Yellow
    } elseif ($null -eq $appUpgrades) {
        Write-Host "   [INFO] WinGet non disponible ou aucune donnée de mise à jour." -ForegroundColor Gray
    } else {
        Write-Host "   [OK] Aucune mise à jour applicative détectée via WinGet." -ForegroundColor Green
    }
}
catch {
    Write-Warning "Erreur lors de l'audit des applications installées : $($_.Exception.Message)"
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

########## LLMNR Audit ##########
Write-Host "`n[+] Audit de la configuration LLMNR :" -ForegroundColor Gray
$llmnrAudit = Get-LLMNRState

if (-not $llmnrAudit.Value) {
    Write-Host "   [DEFAULT] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
} elseif ($llmnrAudit.Value -eq 1) {
    Write-Host "   [ENABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
} elseif ($llmnrAudit.Value -eq 0) {
    Write-Host "   [DISABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Green
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Green
} else {
    Write-Host "   [UNKNOWN] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Yellow
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
}

########## NETBIOS Audit ##########
Write-Host "`n[+] Audit de la configuration NetBIOS :" -ForegroundColor Gray
$netbiosAudit = Get-NetBiosInfo

if ($netbiosAudit -and $netbiosAudit.Count -gt 0) {
    foreach ($adapter in $netbiosAudit) {
        Write-Host "`n   Interface: $($adapter.Interface)" -ForegroundColor Cyan
        Write-Host "   Statut NetBIOS: $($adapter.NetBIOS_Status)" -ForegroundColor Gray
        Write-Host "   Code TcpipNetbiosOptions: $($adapter.TcpipNetbiosOptions)" -ForegroundColor Gray
        
        # Affichage conditionnel selon le statut
        switch ($adapter.TcpipNetbiosOptions) {
            2 {
                Write-Host "   [OK] $($adapter.Recommendation)" -ForegroundColor Green
            }
            1 {
                Write-Host "   [ALERTE] $($adapter.Recommendation)" -ForegroundColor Red
            }
            0 {
                Write-Host "   [MOYEN] $($adapter.Recommendation)" -ForegroundColor Red
            }
            default {
                Write-Host "   [INFORMATION] $($adapter.Recommendation)" -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Error "Impossible d'auditer la configuration NetBIOS"
}

########## FIREWALL Audit ##########
Write-Host "`n[+] Audit du pare-feu (Windows Firewall) :" -ForegroundColor Gray
$fwAudit = Get-FirewallAudit

if ($fwAudit) {

    # État du service Firewall
    if ($fwAudit.FirewallServiceStatus -eq 'NotFound') {
        Write-Host "   [INFORMATION] Le service Windows Firewall (mpssvc) n'a pas été trouvé." -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
    }
    elseif (-not $fwAudit.FirewallServiceRunning) {
        Write-Host "   [ALERTE] Le service Windows Firewall existe mais n'est pas démarré : $($fwAudit.FirewallServiceStatus)" -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
    }
    else {
        Write-Host "   [OK] Le service Windows Firewall est en cours d'exécution." -ForegroundColor Green
        Write-Host "   [PROFIL ACTIF] : $($fwAudit.ActiveProfile)" -ForegroundColor Gray
    }

    # Détails et recommandations RDP
    if ($fwAudit.RdpRuleDetails -and $fwAudit.RdpRuleDetails.Count -gt 0) {
        Write-Host "`n   Règles RDP détectées (nom / LocalAddress / RemoteAddress) :" -ForegroundColor Gray
        foreach ($r in $fwAudit.RdpRuleDetails) {
            Write-Host "      - $($r.Name)    Local: $($r.LocalAddress)    Remote: $($r.RemoteAddress)" -ForegroundColor Yellow
        }

        if ($fwAudit.RdpRecommendations -and $fwAudit.RdpRecommendations.Count -gt 0) {
            Write-Host "`n   Recommandations RDP :" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) { Write-Host "      - $rec" -ForegroundColor Yellow }
        }
    }
    else {
        Write-Host "`n   [INFO] Aucune règle RDP activée détectée." -ForegroundColor Gray
        if ($fwAudit.RdpRecommendations -and $fwAudit.RdpRecommendations.Count -gt 0) {
            Write-Host "   Recommandation : $($fwAudit.RdpRecommendations -join '; ')" -ForegroundColor Yellow
        }
    }

    # Recommandations globales
    if ($fwAudit.GlobalRecommendations -and $fwAudit.GlobalRecommendations.Count -gt 0) {
        Write-Host "`n   Recommandations globales :" -ForegroundColor Yellow
        foreach ($g in $fwAudit.GlobalRecommendations) { Write-Host "      - $g" -ForegroundColor Yellow }
    }
}
else {
    Write-Error "Impossible d'auditer le pare-feu (Get-FirewallAudit n'a pas retourné de résultat)"
}

########## VPN Audit ##########
Write-Host "`n[+] Audit des connexions VPN :" -ForegroundColor Gray
$vpnStatus = Get-VPNStatus

if ($null -ne $vpnStatus) {
    Write-Host "   Description : $($vpnStatus.Description)" -ForegroundColor Gray

    if ($vpnStatus.HasVpnAdapters) {
        Write-Host "`n   Interfaces VPN/TAP/TUN actives détectées :" -ForegroundColor Gray
        foreach ($a in $vpnStatus.Adapters) {
            Write-Host "      - $($a.Name) | $($a.InterfaceDescription) | $($a.Status)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [INFO] Aucune interface VPN/TAP/TUN active détectée." -ForegroundColor Gray
    }

    if ($vpnStatus.HasVpnProfiles) {
        Write-Host "`n   Profils VPN configurés : $($vpnStatus.VpnProfiles.Count)" -ForegroundColor Gray
        if ($vpnStatus.HasActiveVpnProfiles) {
            Write-Host "   Profils VPN connectés : $($vpnStatus.ActiveVpnProfiles.Count)" -ForegroundColor Green
        } else {
            Write-Host "   Aucun profil VPN actuellement connecté." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [INFO] Aucun profil VPN configuré via le client Windows." -ForegroundColor Gray
    }
} else {
    Write-Error "Impossible d'auditer le VPN (Get-VPNStatus n'a pas retourné de résultat)"
}

##########################################
#           OS Security Audit            #
##########################################

########## Optional Features Audit ##########

Write-Host "`n[+] Audit des fonctionnalités optionnelles (Windows Optional Features) :" -ForegroundColor Gray
try {
    $optFeatures = Get-OptionalFeaturesAudit

    if ($optFeatures -and $optFeatures.Count -gt 0) {
        Write-Host "   [INFO] Nombre de fonctionnalités optionnelles activées : $($optFeatures.Count)" -ForegroundColor Gray

        # Affichage synthétique
        $optFeatures |
            Select-Object FeatureName, State,
                @{Name='Risk';Expression={ if ($_.RiskNote) { $_.RiskNote } else { 'Aucun risque spécifique détecté' } } },
                Recommendation |
            Sort-Object @{Expression={ if ($_.Risk -ne 'Aucun risque spécifique détecté') { 0 } else { 1 } } }, FeatureName |
            Format-Table -AutoSize

        # Affichage détaillé des éléments à risque
        $risky = $optFeatures | Where-Object { $_.RiskNote -ne '' }
        if ($risky -and $risky.Count -gt 0) {
            Write-Host "`n   [ATTENTION] Fonctions potentiellement dangereuses / exposées :" -ForegroundColor Yellow
            foreach ($f in $risky) {
                Write-Host "      - $($f.FeatureName) : $($f.RiskNote)" -ForegroundColor Yellow
                Write-Host "         Recommandation : $($f.Recommendation)" -ForegroundColor Yellow
                Write-Host "         Action suggérée (exemple) : Disable-WindowsOptionalFeature -Online -FeatureName `"$($f.FeatureName)`" -NoRestart" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "   [OK] Aucune fonctionnalité optionnelle notablement risquée détectée." -ForegroundColor Green
        }
    } else {
        Write-Host "   [INFO] Aucune fonctionnalité optionnelle activée détectée." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Erreur lors de l'audit des fonctionnalités optionnelles : $($_.Exception.Message)"
}


########## AppLocker Audit ##########

Write-Host "`n[+] Audit de la configuration AppLocker :" -ForegroundColor Gray
try {
    $appLockerState = Get-AppLockerState

    if ($appLockerState) {
        if ($appLockerState.AppLockerPresent) {
            # AppLocker est présent
            if ($appLockerState.AnyRuleEnabled) {
                Write-Host "   [OK] AppLocker est présent et au moins une collection de règles est en mode Enforced." -ForegroundColor Green
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Green
            } else {
                Write-Host "   [INFO] AppLocker est présent mais aucune collection de règles n'est en mode Enforced." -ForegroundColor Yellow
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
            }
        } else {
            # Aucune politique AppLocker effective
            Write-Host "   [ALERTE] Aucune politique AppLocker effective détectée sur ce système." -ForegroundColor Red
            Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
        }

        # Affichage de la recommandation
        Write-Host "       Recommandation : $($appLockerState.Recommendation)" -ForegroundColor Yellow
    } else {
        Write-Error "Impossible d'auditer AppLocker (Get-AppLockerState n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-AppLockerState a échoué : $($_.Exception.Message)"
}


########## SRP Audit ##########

Write-Host "`n[+] Audit de la configuration SRP (Software Restriction Policies) :" -ForegroundColor Gray
try {
    $srpAudit = Get-SRPState

    if ($srpAudit -and $srpAudit.Count -gt 0) {
        foreach ($srp in $srpAudit) {
            Write-Host "`n   Scope: $($srp.Scope)" -ForegroundColor Cyan
            
            if ($srp.SRPPresent) {
                Write-Host "   [DÉTECTÉ] SRP est configuré pour ce scope." -ForegroundColor Yellow
            } else {
                Write-Host "   [ABSENT] Aucune SRP détectée pour ce scope." -ForegroundColor Green
            }
            
            Write-Host "   Chemin du registre: $($srp.RegistryPath)" -ForegroundColor Gray
            Write-Host "   Statut: $($srp.Comment)" -ForegroundColor Gray
            Write-Host "   Recommandation: $($srp.Recommendation)" -ForegroundColor Yellow
        }
    } else {
        Write-Error "Impossible d'auditer SRP (Get-SRPState n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-SRPState a échoué : $($_.Exception.Message)"
}


########## Server Antivirus Status Audit ##########

Write-Host "`n[+] Audit de l'état des services antivirus :" -ForegroundColor Gray
$antivirusStatus = Get-ServerAntivirusStatus

if ($antivirusStatus) {
    foreach ($av in $antivirusStatus) {
        Write-Host "`nService : $($av.Name)" -ForegroundColor Cyan
        
        if ($av.Present -eq $false) {
            Write-Host "   [ALERTE] Aucune solution antivirus détectée sur ce serveur." -ForegroundColor Red
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
        } else {
            # Statut du service
            if ($av.ServiceRunning) {
                Write-Host "   [OK] Le service antivirus est en cours d'exécution." -ForegroundColor Green
            } else {
                Write-Host "   [ALERTE] Le service antivirus n'est pas en cours d'exécution." -ForegroundColor Red
            }

            # Monitoring en temps réel (pour Defender uniquement)
            if ($null -ne $av.RealtimeMonitoring) {
                if ($av.RealtimeMonitoring) {
                    Write-Host "   [OK] La protection en temps réel est activée." -ForegroundColor Green
                } else {
                    Write-Host "   [ALERTE] La protection en temps réel est désactivée." -ForegroundColor Red
                }
            }

            # Status global
            if ($av.OverallProtected) {
                Write-Host "   [OK] Protection globale : Active" -ForegroundColor Green
            } else {
                Write-Host "   [ALERTE] Protection globale : Inactive ou dégradée" -ForegroundColor Red
            }

            # Contexte serveur
            if ($av.IsDomainController) {
                Write-Host "   [INFO] Cette machine est un contrôleur de domaine." -ForegroundColor Magenta
            }

            # Description et recommandation
            Write-Host "   Description : $($av.Description)" -ForegroundColor Gray
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Error "Impossible d'auditer l'état des services antivirus (Get-ServerAntivirusStatus n'a pas retourné de résultat)"
}


########## LM Hash Status Audit ##########

Write-Host "`n[+] Audit de la configuration LM Hash :" -ForegroundColor Gray
try {
    $lmHashStatus = Get-LMHashStatus

    if ($lmHashStatus -and $lmHashStatus.Value) {
        $lm = $lmHashStatus.Value

        Write-Host "   Path: $($lm.Path)" -ForegroundColor Gray
        Write-Host "   NoLMHash Value: $($lm.NoLMHash)" -ForegroundColor Gray

        if ($lm.LMStored -eq $true) {
            Write-Host "   [ALERTE] Les hachs LM peuvent être stockés sur ce système." -ForegroundColor Red
            Write-Host "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [OK] Les hachs LM ne sont pas stockés (NoLMHash = 1)." -ForegroundColor Green
            Write-Host "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
        }

        # Affichage des actions proposées
        if ($lmHashStatus.Xml) {
            Write-Host "`n   Action proposée :" -ForegroundColor Gray
            Write-Host "      - $($lmHashStatus.Xml.Category) : $($lmHashStatus.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($lmHashStatus.Xml.Command)" -ForegroundColor DarkGray
        }
    } else {
        Write-Error "Impossible d'auditer la configuration LM Hash (Get-LMHashStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-LMHashStatus a échoué : $($_.Exception.Message)"
}


########## LSASS Protection Audit ##########

Write-Host "`n[+] Audit de la protection LSASS :" -ForegroundColor Gray
try {
    $lsassAudit = Get-LsassProtectionStatus

    if ($lsassAudit -and $lsassAudit.Value) {
        $p = $lsassAudit.Value

        Write-Host "   LSA Path : $($p.LsaPath)" -ForegroundColor Gray
        Write-Host "   RunAsPPL : $($p.RunAsPPL)" -ForegroundColor Gray

        switch ($p.RunAsPPL) {
            2 {
                Write-Host "   [OK] LSA protection activée (RunAsPPL = 2, Secure Boot requis)." -ForegroundColor Green
            }
            1 {
                Write-Host "   [OK] LSA protection activée (RunAsPPL = 1)." -ForegroundColor Green
            }
            default {
                Write-Host "   [ALERTE] LSA protection non activée ou valeur inconnue." -ForegroundColor Red
            }
        }

        Write-Host "   WDigest Path : $($p.WDigestPath)" -ForegroundColor Gray
        Write-Host "   UseLogonCredential : $($p.UseLogonCredential)" -ForegroundColor Gray

        if ($p.UseLogonCredential -eq 1) {
            Write-Host "   [ALERTE] WDigest activé — mots de passe potentiellement stockés en clair dans LSASS." -ForegroundColor Red
            Write-Host "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [OK] WDigest désactivé ou valeur explicite présente." -ForegroundColor Green
            Write-Host "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        }

        if ($lsassAudit.Xml -and $lsassAudit.Xml.Count -gt 0) {
            Write-Host "`n   Actions proposées :" -ForegroundColor Gray
            foreach ($item in $lsassAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Error "Impossible d'auditer LSASS (Get-LsassProtectionStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-LsassProtectionStatus a échoué : $($_.Exception.Message)"
}

########## Credential Guard Audit ##########

Write-Host "`n[+] Audit Credential Guard :" -ForegroundColor Gray
try {
    $cg = Get-CredentialGuardStatus

    if ($cg) {
        Write-Host "   LsaPath        : $($cg.LsaPath)" -ForegroundColor Gray
        Write-Host "   LsaCfgFlags    : $($cg.LsaCfgFlags)" -ForegroundColor Gray
        Write-Host "   Status         : $($cg.CredentialGuard)" -ForegroundColor Gray

        if ($cg.LsaCfgFlags -eq 1 -or $cg.LsaCfgFlags -eq 2) {
            Write-Host "   [OK] Credential Guard activé." -ForegroundColor Green
        } else {
            Write-Host "   [ALERTE] Credential Guard désactivé ou non configuré." -ForegroundColor Red
        }

        Write-Host "   TPM présent    : $($cg.HasTPM)" -ForegroundColor Gray
        Write-Host "   SecureBoot     : $($cg.SecureBoot)" -ForegroundColor Gray
        Write-Host "   Virtualisation : $($cg.Virtualization)" -ForegroundColor Gray

        if (-not $cg.HasTPM -or -not $cg.SecureBoot -or -not $cg.Virtualization) {
            Write-Host "`n   [PREREQUIS MANQUANTS]" -ForegroundColor Yellow
            if (-not $cg.HasTPM)    { Write-Host "      - TPM manquant ou version non supportée." -ForegroundColor Yellow }
            if (-not $cg.SecureBoot){ Write-Host "      - Secure Boot non activé." -ForegroundColor Yellow }
            if (-not $cg.Virtualization) { Write-Host "      - Virtualisation matérielle non présente." -ForegroundColor Yellow }
            Write-Host "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Yellow
        } else {
            Write-Host "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Gray
        }
    }
    else {
        Write-Error "Impossible d'auditer Credential Guard (Get-CredentialGuardStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-CredentialGuardStatus a échoué : $($_.Exception.Message)"
}


########## Device Guard / VBS Audit ##########

Write-Host "`n[+] Audit Device Guard / VBS :" -ForegroundColor Gray
try {
    $dg = Get-DeviceGuardStatus

    if ($dg) {
        Write-Host "   VBS actif         : $($dg.VBS_Active)" -ForegroundColor Gray
        Write-Host "   WDAC actif        : $($dg.WDAC_Active)" -ForegroundColor Gray
        Write-Host "   CI Enforcement    : $($dg.CodeIntegrityPolicyEnforcementStatus)" -ForegroundColor Gray
        Write-Host "   SecurityServicesConfigured : $($dg.SecurityServicesConfigured)" -ForegroundColor Gray
        Write-Host "   SecurityServicesRunning    : $($dg.SecurityServicesRunning)" -ForegroundColor Gray
        Write-Host "   Commentaire       : $($dg.Comment)" -ForegroundColor Gray

        if ($dg.VBS_Active -or $dg.WDAC_Active) {
            Write-Host "   [OK] Virtualization-Based Security (VBS) et/ou WDAC détecté(s)." -ForegroundColor Green
            Write-Host "   Recommandation : $($dg.Recommendation)" -ForegroundColor Gray

            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Audit') {
                Write-Host "   [INFO] WDAC en mode Audit — examiner les journaux et prévoir passage en Enforced si stable." -ForegroundColor Yellow
            }
            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Enforced') {
                Write-Host "   [OK] WDAC / Code Integrity en mode Enforced." -ForegroundColor Green
            }
        }
        else {
            Write-Host "   [ALERTE] Ni VBS ni WDAC activés sur ce système." -ForegroundColor Red
            Write-Host "   Recommandation : $($dg.Recommendation)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Error "Impossible d'auditer Device Guard (Get-DeviceGuardStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-DeviceGuardStatus a échoué : $($_.Exception.Message)"
}



########## Exploit Protection / Process Mitigations Audit ##########

Write-Host "`n[+] Audit Exploit Protection (Process Mitigations) :" -ForegroundColor Gray
try {
    $epAudit = Get-ExploitProtectionStatus

    if ($epAudit -and $epAudit.Value) {
        $ep = $epAudit.Value
        $issues = @()

        Write-Host "   DEP (Data Execution Prevention)            : $($ep.DEP_Enable)" -ForegroundColor Gray
        if (-not $ep.DEP_Enable) { $issues += 'DEP' ; Write-Host "      [ALERTE] DEP non activé." -ForegroundColor Red } else { Write-Host "      [OK] DEP activé." -ForegroundColor Green }

        Write-Host "   CFG (Control Flow Guard)                   : $($ep.CFG_Enable)" -ForegroundColor Gray
        if (-not $ep.CFG_Enable) { $issues += 'CFG' ; Write-Host "      [ALERTE] CFG non activé." -ForegroundColor Red } else { Write-Host "      [OK] CFG activé." -ForegroundColor Green }

        Write-Host "   SEHOP (SEH Overwrite Protection)          : $($ep.SEHOP_Enable)" -ForegroundColor Gray
        if (-not $ep.SEHOP_Enable) { $issues += 'SEHOP' ; Write-Host "      [ALERTE] SEHOP non activé." -ForegroundColor Red } else { Write-Host "      [OK] SEHOP activé." -ForegroundColor Green }

        Write-Host "   ASLR Bottom-Up                              : $($ep.ASLR_BottomUP)" -ForegroundColor Gray
        if (-not $ep.ASLR_BottomUP) { $issues += 'ASLR_BottomUP' ; Write-Host "      [ALERTE] ASLR Bottom-Up non activé." -ForegroundColor Red } else { Write-Host "      [OK] ASLR Bottom-Up activé." -ForegroundColor Green }

        Write-Host "   ASLR High-Entropy                           : $($ep.ASLR_HighEntropy)" -ForegroundColor Gray
        if (-not $ep.ASLR_HighEntropy) { $issues += 'ASLR_HighEntropy' ; Write-Host "      [ALERTE] ASLR High-Entropy non activé." -ForegroundColor Red } else { Write-Host "      [OK] ASLR High-Entropy activé." -ForegroundColor Green }

        Write-Host "   ASLR ForceRelocateImages                    : $($ep.ASLR_ForceRelocateImages)" -ForegroundColor Gray
        if (-not $ep.ASLR_ForceRelocateImages) { $issues += 'ASLR_ForceRelocateImages' ; Write-Host "      [ALERTE] ForceRelocateImages non activé." -ForegroundColor Red } else { Write-Host "      [OK] ForceRelocateImages activé." -ForegroundColor Green }

        Write-Host "`n   Synthèse :" -ForegroundColor Gray
        if ($issues.Count -eq 0) {
            Write-Host "      [OK] Paramètres globaux d'Exploit Protection solides." -ForegroundColor Green
            Write-Host "      Recommandation : $($ep.Recommendation)" -ForegroundColor Gray
        } else {
            Write-Host "      [ALERTE] Paramètres manquants ou désactivés : $($issues -join ', ')" -ForegroundColor Red
            Write-Host "      Recommandation : $($ep.Recommendation)" -ForegroundColor Yellow
        }

        if ($epAudit.Xml -and $epAudit.Xml.Count -gt 0) {
            Write-Host "`n   Actions proposées :" -ForegroundColor Gray
            foreach ($item in $epAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    }
    else {
        Write-Error "Impossible d'auditer Exploit Protection (Get-ExploitProtectionStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-ExploitProtectionStatus a échoué : $($_.Exception.Message)"
}


########## ASR (Attack Surface Reduction) Audit ##########

Write-Host "`n[+] Audit Attack Surface Reduction (ASR) :" -ForegroundColor Gray
try {
    $asrAudit = Get-ASRStatus

    if (-not $asrAudit) {
        Write-Error "Impossible d'auditer ASR (Get-ASRStatus n'a pas retourné de résultat)"
    }
    elseif ($asrAudit -is [System.Collections.IEnumerable] -and $asrAudit.Count -gt 0 -and ($asrAudit | Where-Object { $_.RuleId })) {
        foreach ($rule in $asrAudit) {
            $status = $rule.Action
            switch ($status) {
                'Block'  { $color = 'Green' ; $label = '[ENFORCED]' }
                'Audit'  { $color = 'Yellow'; $label = '[AUDIT]' }
                'Warn'   { $color = 'Magenta'; $label = '[WARN]' }
                'Disabled' { $color = 'Red'; $label = '[DISABLED]' }
                default  { $color = 'Gray'; $label = "[UNKNOWN]" }
            }

            Write-Host "`n   RuleId : $($rule.RuleId)  $label" -ForegroundColor Cyan
            Write-Host "      Mode : $status" -ForegroundColor $color
            Write-Host "      Commentaire : $($rule.Comment)" -ForegroundColor Gray
            if ($rule.Recommendation) { Write-Host "      Recommandation : $($rule.Recommendation)" -ForegroundColor Yellow }
        }
    }
    else {
        # Cas où Get-ASRStatus renvoie un objet unique indiquant l'absence de règles
        Write-Host "   $($asrAudit.Comment)" -ForegroundColor Red
        Write-Host "   Recommandation : $($asrAudit.Recommendation)" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Get-ASRStatus a échoué : $($_.Exception.Message)"
}

########## Network Protection (Defender) Audit ##########

Write-Host "`n[+] Audit Network Protection (Microsoft Defender) :" -ForegroundColor Gray
try {
    $np = Get-NetworkProtectionStatus

    if ($np) {
        Write-Host "   Mode détecté : $($np.Mode)" -ForegroundColor Gray
        switch ($np.Mode) {
            'Block' {
                Write-Host "   [OK] Network Protection en mode Block." -ForegroundColor Green
            }
            'Audit' {
                Write-Host "   [INFO] Network Protection en mode Audit." -ForegroundColor Yellow
            }
            'Off' {
                Write-Host "   [ALERTE] Network Protection désactivé." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Network Protection non configuré." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($np.RawValue)" -ForegroundColor Yellow
            }
        }

        Write-Host "   EnableNetworkProtection : $($np.EnableNetworkProtection)" -ForegroundColor Gray
        Write-Host "`n   Recommandation : $($np.Recommendation)" -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Network Protection (Get-NetworkProtectionStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-NetworkProtectionStatus a échoué : $($_.Exception.Message)"
}


########## Controlled Folder Access (CFA) Audit ##########

Write-Host "`n[+] Audit Controlled Folder Access (Defender) :" -ForegroundColor Gray
try {
    $cfa = Get-ControlledFolderAccessStatus

    if ($cfa) {
        Write-Host "   Mode détecté : $($cfa.Mode)" -ForegroundColor Gray

        switch ($cfa.Mode) {
            'Block' {
                Write-Host "   [OK] Controlled Folder Access en mode Block." -ForegroundColor Green
            }
            'Audit' {
                Write-Host "   [INFO] Controlled Folder Access en mode Audit." -ForegroundColor Yellow
            }
            'Block disk modification only' {
                Write-Host "   [INFO] CFA en mode 'Block disk modification only'." -ForegroundColor Yellow
            }
            'Audit disk modification only' {
                Write-Host "   [INFO] CFA en mode 'Audit disk modification only'." -ForegroundColor Yellow
            }
            'Off' {
                Write-Host "   [ALERTE] Controlled Folder Access désactivé." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Controlled Folder Access non configuré." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($cfa.EnableControlledFolderAccess)" -ForegroundColor Yellow
            }
        }

        Write-Host "`n   Recommandation : $($cfa.Recommendation)" -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Controlled Folder Access (Get-ControlledFolderAccessStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-ControlledFolderAccessStatus a échoué : $($_.Exception.Message)"
}


########## Smart App Control Audit ##########

Write-Host "`n[+] Audit Smart App Control :" -ForegroundColor Gray
try {
    $sac = Get-SmartAppControlStatus

    if ($sac) {
        Write-Host "   Smart App Control : $($sac.SmartApp_State)" -ForegroundColor Gray

        switch ($sac.SmartApp_State) {
            'On' {
                Write-Host "   [OK] Smart App Control activé." -ForegroundColor Green
            }
            'Evaluation' {
                Write-Host "   [INFO] Smart App Control en mode Evaluation." -ForegroundColor Yellow
            }
            'Off' {
                Write-Host "   [ALERTE] Smart App Control désactivé." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Smart App Control non configuré." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur détectée : $($sac.SmartApp_State)" -ForegroundColor Yellow
            }
        }

        Write-Host "`n   Recommandation : Tester en mode Evaluation puis activer (On) sur systèmes compatibles." -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Smart App Control (Get-SmartAppControlStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-SmartAppControlStatus a échoué : $($_.Exception.Message)"
}


########## PowerShell Language Mode Audit ##########

Write-Host "`n[+] Audit du mode langage PowerShell :" -ForegroundColor Gray
try {
    $psMode = Get-PowerShellLanguageMode

    if ($psMode) {
        Write-Host "   LanguageMode : $($psMode.LanguageMode)" -ForegroundColor Gray

        if ($psMode.IsConstrained) {
            Write-Host "   [OK] PowerShell en ConstrainedLanguage." -ForegroundColor Green
            Write-Host "   Recommandation : $($psMode.Recommendation)" -ForegroundColor Gray
        }
        else {
            Write-Host "   [ALERTE] PowerShell en FullLanguage (ou moins restreint)." -ForegroundColor Red
            Write-Host "   Recommandation : $($psMode.Recommendation)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Error "Impossible d'auditer le mode PowerShell (Get-PowerShellLanguageMode n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-PowerShellLanguageMode a échoué : $($_.Exception.Message)"
}


##########################################
#             Device Security            #
##########################################

########## AutoRun / NoDriveTypeAutorun Audit ##########

Write-Host "`n[+] Audit AutoRun (NoDriveTypeAutorun) :" -ForegroundColor Gray
try {
    $ar = Get-AutorunStatus

    if ($ar -and $ar.Value) {
        foreach ($entry in $ar.Value) {
            Write-Host "`n   Scope : $($entry.Scope)" -ForegroundColor Cyan
            Write-Host "      Valeur brute : $($entry.Value)" -ForegroundColor Gray
            Write-Host "      Commentaire  : $($entry.Comment)" -ForegroundColor Gray

            if ($entry.AutoRunEnabled -eq $true) {
                Write-Host "      [ALERTE] Autorun potentiellement activé." -ForegroundColor Red
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Yellow
            }
            else {
                Write-Host "      [OK] Autorun désactivé pour ce scope." -ForegroundColor Green
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Gray
            }
        }

        if ($ar.Xml) {
            Write-Host "`n   Actions proposées :" -ForegroundColor Gray
            Write-Host "      - $($ar.Xml.Category) : $($ar.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($ar.Xml.Command)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Error "Impossible d'auditer AutoRun (Get-AutorunStatus n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-AutorunStatus a échoué : $($_.Exception.Message)"
}

########## BitLocker Audit ##########

Write-Host "`n[+] Audit BitLocker :" -ForegroundColor Gray
try {
    $bitlocker = Get-BitLockerAudit

    if ($bitlocker -and $bitlocker.Count -gt 0) {
        foreach ($vol in $bitlocker) {
            Write-Host "`n   Volume : $($vol.MountPoint) ($($vol.VolumeType))" -ForegroundColor Cyan
            Write-Host "      ProtectionStatus   : $($vol.ProtectionStatus)  |  Chiffrement : $($vol.EncryptionPercent)% " -ForegroundColor Gray
            if ($vol.ProtectionStatus -eq 'On' -and $vol.EncryptionPercent -ge 100) {
                Write-Host "      [OK] Volume chiffré et protégé." -ForegroundColor Green
            }
            elseif ($vol.ProtectionStatus -eq 'Suspended') {
                Write-Host "      [INFO] Protection suspendue." -ForegroundColor Yellow
            }
            else {
                Write-Host "      [ALERTE] Volume non protégé ou chiffrement incomplet." -ForegroundColor Red
            }

            Write-Host "      TPM : $($vol.HasTPM)    PIN : $($vol.HasPIN)    RecoveryKey : $($vol.HasRecoveryPassword)" -ForegroundColor Gray
            Write-Host "      Commentaire : $($vol.Comment)" -ForegroundColor Gray
            Write-Host "      Recommandation : $($vol.Recommendation)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Error "Impossible d'auditer BitLocker (Get-BitLockerAudit n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-BitLockerAudit a échoué : $($_.Exception.Message)"
}


########## Third‑Party Full Disk Encryption Indicators ##########

Write-Host "`n[+] Audit indicateurs de chiffrement tiers :" -ForegroundColor Gray
try {
    $tpe = Get-ThirdPartyEncryptionIndicators

    if ($null -eq $tpe) {
        Write-Error "Get-ThirdPartyEncryptionIndicators n'a pas retourné de résultat"
    }
    elseif ($tpe -is [System.Collections.IEnumerable] -and $tpe.Count -gt 0) {
        foreach ($item in $tpe) {
            # Attendu : propriétés possibles Name, Present, Version, Details, Recommendation
            $name = $item.Name      -or 'ThirdPartyEncryption'
            $present = $item.Present -or $false
            Write-Host "`n   Solution : $name" -ForegroundColor Cyan
            Write-Host "      Présent : $present" -ForegroundColor Gray

            if ($present) {
                Write-Host "      [INFO] Chiffrement tiers détecté : $name" -ForegroundColor Green
                if ($item.Version) { Write-Host "      Version : $($item.Version)" -ForegroundColor Gray }
                if ($item.Details) { Write-Host "      Détails : $($item.Details)" -ForegroundColor Gray }
                if ($item.Recommendation) { Write-Host "      Recommandation : $($item.Recommendation)" -ForegroundColor Yellow }
            } else {
                Write-Host "      [OK] Aucun chiffrement tiers détecté pour cet item." -ForegroundColor Green
            }
        }
    }
    else {
        # Cas objet unique attendu avec propriétés HasThirdParty/Detected/Details/Recommendation
        $has = $tpe.HasThirdParty  -or $tpe.Detected -or $false
        Write-Host "   Indicateur chiffrement tiers détecté : $has" -ForegroundColor Gray
        if ($has) {
            Write-Host "   [INFO] Un chiffrement tiers semble présent. Détails : $($tpe.Details)" -ForegroundColor Green
            if ($tpe.Recommendation) { Write-Host "   Recommandation : $($tpe.Recommendation)" -ForegroundColor Yellow }
        } else {
            Write-Host "   [OK] Aucun chiffrement tiers détecté." -ForegroundColor Purple
        }
    }
}
catch {
    Write-Warning "Get-ThirdPartyEncryptionIndicators a échoué : $($_.Exception.Message)"
}


##########################################
#            Update Management           #
##########################################

########## Last Reboot / Uptime Audit ##########

Write-Host "`n[+] Audit du dernier redémarrage :" -ForegroundColor Gray
try {
    $lr = Get-LastReboot

    if ($lr) {
        Write-Host "   Rôle de la machine : $($lr.ComputerRole)" -ForegroundColor Gray
        Write-Host "   Dernier démarrage   : $($lr.LastBootTime)" -ForegroundColor Gray
        Write-Host "   Uptime              : $($lr.Uptime) (jours: $($lr.UptimeDays))" -ForegroundColor Gray
        Write-Host "   Seuil recommandé    : $($lr.ThresholdDays) jours" -ForegroundColor Gray

        if ($lr.UptimeDays -gt $lr.ThresholdDays) {
            Write-Host "   [ALERTE] Uptime supérieur au seuil ($($lr.ThresholdDays) jours)." -ForegroundColor Red
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Yellow
        }
        else {
            Write-Host "   [OK] Uptime dans la plage attendue." -ForegroundColor Green
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Gray
        }
    }
    else {
        Write-Error "Impossible d'auditer le dernier redémarrage (Get-LastReboot n'a pas retourné de résultat)"
    }
}
catch {
    Write-Warning "Get-LastReboot a échoué : $($_.Exception.Message)"
}

##########################################
#                Logging                 #
##########################################

########## Logging / Event Collection Audit ##########

Write-Host "`n[+] Audit des journaux et de la collecte d'événements :" -ForegroundColor Gray
try {
    # 1) Logs locaux (taille / retention)
    $logs = Get-LogStatus
    if ($logs -and $logs.Count -gt 0) {
        foreach ($l in $logs) {
            Write-Host "`n   Log : $($l.LogName)" -ForegroundColor Cyan
            if (-not $l.IsEnabled) {
                Write-Host "      [ALERTE] Désactivé ou indisponible." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                continue
            }

            Write-Host "      Enregistrés : $($l.RecordCount)  |  MaxSize : $($l.MaximumSizeMB) MB  |  Reco : $($l.RecoSizeMB) MB" -ForegroundColor Gray

            if ($l.IsSizeOK -eq $true) {
                Write-Host "      [OK] Taille du journal conforme." -ForegroundColor Green
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
            }
            elseif ($l.IsSizeOK -eq $false) {
                Write-Host "      [ALERTE] Taille du journal insuffisante." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
            }
            else {
                Write-Host "      [INFO] Aucune recommandation de taille définie." -ForegroundColor Yellow
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Error "Get-LogStatus n'a pas retourné de résultat."
    }

    # 2) Event Forwarding & Sysmon
    $ef = Get-EventForwardingStatus
    if ($ef -and $ef.Count -gt 0) {
        foreach ($e in $ef) {
            Write-Host "`n   Source : $($e.Name)" -ForegroundColor Cyan
            Write-Host "      Activé : $($e.IsEnabled)" -ForegroundColor Gray
            Write-Host "      Commentaire : $($e.Comment)" -ForegroundColor Gray
            Write-Host "      Recommendation : $($e.Recommendation)" -ForegroundColor Yellow
        }
    } else {
        Write-Warning "Get-EventForwardingStatus n'a pas retourné de résultat."
    }

    # 3) Recherche d'agents de logs / SIEM
    $agents = Get-LogAgentStatus
    if ($agents -and $agents.Count -gt 0) {
        Write-Host "`n   Agents de collecte détectés :" -ForegroundColor Gray
        foreach ($a in $agents) {
            if ($a.IsLogAgent) {
                Write-Host "      - $($a.DisplayName) (version: $($a.DisplayVersion))" -ForegroundColor Green
                Write-Host "         Recommendation : $($a.Recommendation)" -ForegroundColor Gray
            } else {
                Write-Host "      - Aucun agent connu détecté sur l'entrée (bruit possible)." -ForegroundColor Yellow
                Write-Host "         Commentaire : $($a.Comment)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "`n   [ALERTE] Aucun agent de collecte/SIEM détecté." -ForegroundColor Red
        Write-Host "      Recommendation : Installer/configurer un agent pour centraliser les logs." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Audit Logging a échoué : $($_.Exception.Message)"
}


# --- Fin ---
Write-Host "`nAudit terminé." -ForegroundColor Cyan

