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

# --- Execution de l'Audit ---
Write-Host "Demarrage de l'audit sur $env:COMPUTERNAME..." -ForegroundColor Green

# 1. Recuperation du contexte (appel de notre fonction importee)
$context = Get-HostContext

if ($context) {
    Write-Host "`n[+] Contexte Identifie :" -ForegroundColor Yellow
    $context | Format-List
    
    # Logique conditionnelle base sur le contexte
    if ($context.OSRole -eq "Server") {
        Write-Host ">> Mode Audit Serveur active." -ForegroundColor Gray
    }
    elseif ($context.HardwareType -eq "Virtual Machine") {
        Write-Host ">> Machine Virtuelle detectee : Verification des Integration Tools requise." -ForegroundColor Gray
    }
}
else {
    Write-Error "Impossible de determiner le contexte de la machine."
}

######################################
#       Account Security Audits      #
######################################


########## Local User Audit ##########

$localUserAudit = Get-LocalUserAudit

if ($localUserAudit) {
    Write-Host "`n[+] Compte locaux identifies :" -ForegroundColor Gray
    
    if (($localUserAudit.Value.AdminAccountSID -match "-500$") -and ($localUserAudit.Value.AdminEnabled -eq $true)){
        Write-Host "`nLe compte Administrateur par defaut est active" -ForegroundColor Red
        Write-Host $localUserAudit.Value.AdminRecommandation.Enabled -ForegroundColor Yellow     
    }
    else {
        Write-Host $localUserAudit.Value.AdminRecommandation.Disabled -ForegroundColor Green
    }

    if (($localUserAudit.Value.GuestAccountSID -match "-501$") -and ($localUserAudit.Value.GuestEnabled -eq $true)){
        Write-Host "`nLe compte Invite par defaut est active" -ForegroundColor Red
        Write-Host $localUserAudit.Value.GuestRecommandation.Enabled -ForegroundColor Yellow
    } else {
        Write-Host $localUserAudit.Value.GuestRecommandation.Disabled -ForegroundColor Green
    }
}
else {
    Write-Error "Impossible d'auditer les utilisateurs locaux"
}



########## Privilege Audit ##########

$privilegeAudits = Get-Privilege

foreach ($audit in $privilegeAudits) {
    Write-Host "`n[+] Audit du privilege $($audit.Privilege) :" -ForegroundColor Gray
    
    if ($audit.Configured) {
        Write-Host "Privilege configure : $($audit.Privilege)" -ForegroundColor Yellow
        Write-Host "Assigne a : $($audit.AssignedTo -join ', ')" -ForegroundColor Gray
        Write-Host "Administrateurs presents : $($audit.IsAdminPresent)" -ForegroundColor Gray
        Write-Host "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
    } else {
        Write-Host "Privilege non configure." -ForegroundColor Green
        Write-Host "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
    }
}



########## LAPS Audit ##########

$lapsAudit = Get-LAPSAudit
Write-Host "`n[+] Audit de la configuration LAPS :" -Foregroundcolor Gray

if ($lapsaudit){

    if ($context.Domainjoined -eq $true) {

        # Affichage dynamique selon le resultat
        switch ($lapsAudit.Status) {
            "PASS" {
                Write-Host "   [OK] $($lapsAudit.DetectedMethods)" -ForegroundColor Green
                # Si on a un warning mineur (ex: Legacy + Modern en meme temps)
                if ($lapsAudit.Recommendation -match "ATTENTION") {
                    Write-Host "   $($lapsAudit.Recommendation)" -ForegroundColor Magenta
                }
            }
            "WARNING" {
                # Cas specifique Legacy seul
                Write-Host "   [OBSOLETE] $($lapsAudit.DetectedMethods)" -ForegroundColor Orange
                Write-Host "   -> $($lapsAudit.Recommendation)" -ForegroundColor Yellow
            }
            "FAIL" {
                Write-Host "   [ALERTE] $($lapsAudit.Recommendation)" -ForegroundColor Red
            }
        }

    }
    else {
        Write-Host "`rLa machine n'est pas jointe a un domaine. LAPS n'est pas auditable" -ForegroundColor Magenta
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

            # Affichage Complexite
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
            Write-Host "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe AD"
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

            # Affichage Complexite
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
            Write-Host "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe"
        }
    }
}



########## Authentication Level Audit ##########

Write-Host "`n[+] Audit du niveau d'authentification :" -Foregroundcolor Gray
$authLevelAudit = Get-AuthenticationLevelAudit

if ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $true) {
    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $false) {
    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [OK] Windows Hello (Consumer/Local) est active." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $true) {
    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $false) {
    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) est active. Il est plutot recommande de desactiver cette fonctionnalite sur les serveurs." -ForegroundColor Red
    } else {
        Write-Host "   [OK] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Green
    }
} else {
    Write-Host "   [INFORMATION] Le niveau d'authentification n'a pas pu etre audite dans ce contexte." -ForegroundColor Yellow
}

########## UAC Audit ##########
Write-Host "`n[+] Audit de la configuration de l'UAC :" -Foregroundcolor Gray
$uacAudit = Get-UACAudit

try {
    if ($uacAudit.UACEnabled -eq 1) {
        Write-Host "   [OK] L'UAC est active." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] L'UAC est desactive." -ForegroundColor Red
    }

    if ($uacAudit.FilterAdministratorToken -eq 1) {
        Write-Host "   [OK] Le filtrage du token administrateur est active." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] Le filtrage du token administrateur est desactive." -ForegroundColor Red
    }

    if ($uacAudit.LocalAccountTokenFilterPolicy -eq 1) {
        Write-Host "   [OK] La politique de filtrage des tokens pour les comptes locaux est activee." -ForegroundColor Green
    } else {
        Write-Host "   [ALERTE] La politique de filtrage des tokens pour les comptes locaux est desactivee (risque d'acces non administrateur via le reseau)." -ForegroundColor Red
    }
}
catch {
    Write-Host "Erreur lors de l'affichage des resultats de l'audit UAC"
}



########## JEA Audit ##########

Write-Host "`n[+] Audit de la configuration JEA :" -Foregroundcolor Gray
$JEAAudit = Get-JEAAudit
try {
    if ($JEAAudit.WinRmState -eq 'NotInstalled'){
        Write-Host "   [INFORMATION] WinRM n'est pas installe. JEA ne peut pas etre configure." -ForegroundColor Red
    } elseif ($JEAAudit.WinRmState -eq 'Stopped') {
        Write-Host "   [ALERTE] WinRM est installe mais arrete. JEA ne peut pas etre utilise tant que WinRM n'est pas demarre." -ForegroundColor Red
    } elseif ($JEAAudit.HasJEASessionConfig -eq $true){
        Write-Host "   [OK] Des endpoints JEA sont configures sur cette machine." -ForegroundColor Green
        Write-Host "       $($JEAAudit.Recommandation)" -ForegroundColor Gray
    } elseif ($JEAAudit.HasJEASessionConfig -eq $false){
        Write-Host "   [ALERTE] WinRM est fonctionnel mais aucun endpoint JEA n'est configure." -ForegroundColor Red
    } else {
        Write-Error "   [ERREUR] Impossible d'auditer la configuration JEA." -ForegroundColor Red
    }
} catch {
    Write-Host "Erreur lors de l'affichage des resultats de l'audit JEA"
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
                Write-Host "   [ALERTE] Ce groupe contient un grand nombre de membres ($($group.MembersCount)). Verifiez qu'il n'y a pas d'utilisateurs non autorises." -ForegroundColor Red
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
        Write-Host "   [ACTIVE] RDP est active sur cette machine." -ForegroundColor Red
    }
    else {
        Write-Host "   [DESACTIVE] RDP est desactive au niveau OS." -ForegroundColor Green
    }

    Write-Host "   [ADMIN RESTREINT] DisableRestrictedAdmin : $($r.DisableRestrictedAdmin)" -ForegroundColor Gray
    Write-Host "   [CHIFFREMENT] MinEncryptionLevel : $($r.MinEncryptionLevel)" -ForegroundColor Gray
    Write-Host "   [COUCHE DE SECURITE] SecurityLayer : $($r.SecurityLayer)" -ForegroundColor Gray
    Write-Host "   [NLA] UserAuthentication : $($r.UserAuthentication)" -ForegroundColor Gray

    if ($r.fEncryptRPCTraffic -eq $true) {
        Write-Host "   [RPC] fEncryptRPCTraffic : Active" -ForegroundColor Green
    } else {
        Write-Host "   [RPC] fEncryptRPCTraffic : Desactive" -ForegroundColor Red
    }

    if ($r.Recommendation) {
        Write-Host "`n   Recommandation : $($r.Recommendation)" -ForegroundColor Yellow
    }

    if ($rdpAudit.Xml) {
        Write-Host "`n   Actions proposees :" -ForegroundColor Gray
        foreach ($item in $rdpAudit.Xml) {
            Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
        }
    }

} else {
    Write-Error "Impossible d'auditer RDP (Get-RDPAudit n'a pas retourne de resultat)"
}



########## WinRM Audit ##########

Write-Host "`n[+] Audit WinRM :" -ForegroundColor Gray
try {
    $winrmAudit = Get-WinRMAudit

    if (-not $winrmAudit.WinRmEnabled) {
        Write-Host "   [INACTIF] WinRM n'est pas installe ou le service est arrete." -ForegroundColor Purple
        Write-Host "   Recommandation :" -ForegroundColor Yellow
        foreach ($r in $winrmAudit.Recommendations) { Write-Host "      - $r" -ForegroundColor Yellow }
    }
    else {
        Write-Host "   [ACTIF] WinRM est active." -ForegroundColor Yellow
        Write-Host "   [TRANSPORT] ListenerTransport : $($winrmAudit.ListenerTransport)" -ForegroundColor Gray
        Write-Host "   [ECOUTE] ListeningOn        : $($winrmAudit.ListeningOn)" -ForegroundColor Gray
        Write-Host "   [FILTRES IP] IPv4 : $($winrmAudit.IPv4Filter)    IPv6 : $($winrmAudit.IPv6Filter)" -ForegroundColor Gray

        if ($winrmAudit.ServiceAuth) {
            Write-Host "   [AUTHENTIFICATION SERVICE] Basic : $($winrmAudit.ServiceAuth.Basic)    Unencrypted : $($winrmAudit.ServiceAuth.Unencrypted)" -ForegroundColor Gray
        }
        if ($winrmAudit.ClientAuth) {
            Write-Host "   [AUTHENTIFICATION CLIENT]  Basic : $($winrmAudit.ClientAuth.Basic)" -ForegroundColor Gray
        }

        if ($winrmAudit.RmUsersNotAdmins) {
            Write-Host "   [UTILISATEURS] Comptes dans Remote Management Users (non-admin) : $($winrmAudit.RmUsersNotAdmins -join ', ')" -ForegroundColor Yellow
        }

        if ($winrmAudit.Recommendations) {
            Write-Host "`n   Recommandations :" -ForegroundColor Yellow
            foreach ($rec in $winrmAudit.Recommendations) {
                Write-Host "      - $rec" -ForegroundColor Yellow
            }
        } else {
            Write-Host "   [OK] Configuration WinRM conforme aux bonnes pratiques detectee." -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Get-WinRMAudit a echoue : $($_.Exception.Message)"
}



########## SMB Audit ##########

Write-Host "`n[+] Audit SMB :" -ForegroundColor Gray

try {
    $smbAudit = Get-SMBAudit

    if ($smbAudit -and $smbAudit.Value) {
        $s = $smbAudit.Value

        # Affichage du statut SMBv1
        if ($s.SMBv1State -eq $true) {
            Write-Host "   [SMBv1] [ALERTE] SMBv1 est active. Il est recommande de le desactiver." -ForegroundColor Red
        } else {
            Write-Host "   [SMBv1] [OK] SMBv1 est desactive." -ForegroundColor Green
        }

        # Affichage du statut SMBv2/3
        if ($s.SMBv2State -eq $true) {
            Write-Host "   [SMBv2/3] [OK] SMBv2/3 est active." -ForegroundColor Green
        } else {
            Write-Host "   [SMBv2/3] [ALERTE] SMBv2/3 est desactive." -ForegroundColor Red
        }

        # Affichage du statut de la signature SMB
        if ($s.RequireSecuritySignature -eq $true) {
            Write-Host "   [SIGNING] [OK] La signature de securite SMB est requise." -ForegroundColor Green
        } else {
            Write-Host "   [SIGNING] [ALERTE] La signature de securite SMB n'est pas requise." -ForegroundColor Red
        }

        if ($s.Comment) {
            Write-Host "`n   Details : $($s.Comment)" -ForegroundColor Gray
        }

        if ($s.Recommendation) {
            Write-Host "`n   Recommandation : $($s.Recommendation)" -ForegroundColor Yellow
        }

        # Affichage des actions proposees
        if ($smbAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $smbAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Error "Impossible d'auditer SMB (Get-SMBAudit n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-SMBAudit a echoue : $($_.Exception.Message)"
}


########### Update Audit ##########

Write-Host "`n[+] Audit des mises a jour et version OS :" -ForegroundColor Gray
try {
    $osInfo = Get-OSVersionInfo
    if ($osInfo) {
        Write-Host "`n[OS] $($osInfo.Caption) - Version $($osInfo.Version) (Full: $($osInfo.FullVersion))" -ForegroundColor Cyan
        if ($osInfo.InstallDate) {
            $installDate = [datetime]$osInfo.InstallDate
            Write-Host "Build: $($osInfo.BuildNumber)   Installe le: $($installDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
        } else {
            Write-Host "Build: $($osInfo.BuildNumber)   InstallDate: Non disponible" -ForegroundColor Gray
        }
    }

    $updateSource = Get-UpdateSource
    Write-Host "`n[Source de mises a jour] $updateSource" -ForegroundColor Gray

    $kbList = Get-InstalledKB
    if ($kbList) {
        Write-Host "`n[+] Dernieres mises a jour installees (10 dernieres) :" -ForegroundColor Gray
        $kbList | Select-Object -First 10 | Format-Table HotFixID, Description, @{Name='InstalledOn';Expression={ ($_.InstalledOn -as [datetime]).ToString('yyyy-MM-dd') }}, InstalledBy -AutoSize
    } else {
        Write-Host "Aucune mise a jour detectee via Get-HotFix" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Erreur lors de la collecte des informations de mise a jour : $($_.Exception.Message)"
}

########## Installed Applications Audit ##########

Write-Host "`n[+] Audit des applications installees :" -ForegroundColor Gray
try {
    $apps = Get-InstalledApplications

    if ($apps) {
        Write-Host "   [INFO] Nombre d'applications detectees : $(($apps | Measure-Object).Count)" -ForegroundColor Gray
        $apps | Select-Object Name, Version, Publisher, InstallLocation |
            Sort-Object Name |
            Format-Table -AutoSize
    } else {
        Write-Host "   [INFO] Aucune application installee detectee." -ForegroundColor Yellow
    }

    # Verification des mises a jour applicatives via WinGet (si disponible)
    $appUpgrades = Get-AppUpgrade -ErrorAction SilentlyContinue
    if ($appUpgrades) {
        Write-Host "`n   [Mises a jour disponibles via WinGet] :" -ForegroundColor Yellow
        $appUpgrades |
            Select-Object Name, InstalledVersion, @{Name='Available';Expression={$_.AvailableVersions -join ','}} |
            Format-Table -AutoSize
        Write-Host "   Recommandation : utiliser `winget upgrade --all` pour mettre a jour les applications prises en charge." -ForegroundColor Yellow
    } elseif ($null -eq $appUpgrades) {
        Write-Host "   [INFO] WinGet non disponible ou aucune donnee de mise a jour." -ForegroundColor Gray
    } else {
        Write-Host "   [OK] Aucune mise a jour applicative detectee via WinGet." -ForegroundColor Green
    }
}
catch {
    Write-Warning "Erreur lors de l'audit des applications installees : $($_.Exception.Message)"
}

######################################
#      Network Security Audits       #
######################################

########## IPv6 Audit ##########
Write-Host "`n[+] Audit de la configuration IPv6 :" -ForegroundColor Gray
$ipv6Audit = Get-IPv6Status

if ($ipv6Audit) {
    foreach ($adapter in $ipv6Audit) {
        if ($adapter.IPv6Enabled -eq $true) {
            Write-Host "   [ACTIVE] Adaptateur: $($adapter.Adapter) - IPv6 est active." -ForegroundColor Red
            Write-Host "       Recommandation: $($adapter.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [DESACTIVE] Adaptateur: $($adapter.Adapter) - IPv6 est desactive." -ForegroundColor Green
            Write-Host "       Recommandation: $($adapter.Recommendation)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Error "Impossible d'auditer la configuration IPv6 (Get-IPv6Status n'a pas retourne de resultat)"
}

########## LLMNR Audit ##########
Write-Host "`n[+] Audit de la configuration LLMNR :" -ForegroundColor Gray
$llmnrAudit = Get-LLMNRState

if (-not $llmnrAudit.Value) {
    Write-Host "   [PAR DEFAUT] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommandation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
} elseif ($llmnrAudit.Value -eq 1) {
    Write-Host "   [ACTIVE] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommandation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
} elseif ($llmnrAudit.Value -eq 0) {
    Write-Host "   [DESACTIVE] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Green
    Write-Host "       Recommandation: $($llmnrAudit.Recommendation)" -ForegroundColor Green
} else {
    Write-Host "   [INCONNU] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Yellow
    Write-Host "       Recommandation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
}

########## NETBIOS Audit ##########
Write-Host "`n[+] Audit de la configuration NetBIOS :" -ForegroundColor Gray
$netbiosAudit = Get-NetBiosInfo

if ($netbiosAudit) {
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
    Write-Error "Impossible d'auditer la configuration NetBIOS" #-ErrorAction SilentlyContinue
}

########## FIREWALL Audit ##########
Write-Host "`n[+] Audit du pare-feu (Windows Firewall) :" -ForegroundColor Gray
$fwAudit = Get-FirewallAudit

if ($fwAudit) {

    # Etat du service Firewall
    if ($fwAudit.FirewallServiceStatus -eq 'NotFound') {
        Write-Host "   [INFORMATION] Le service Windows Firewall (mpssvc) n'a pas ete trouve." -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
    }
    elseif (-not $fwAudit.FirewallServiceRunning) {
        Write-Host "   [ALERTE] Le service Windows Firewall existe mais n'est pas demarre : $($fwAudit.FirewallServiceStatus)" -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
    }
    else {
        Write-Host "   [OK] Le service Windows Firewall est en cours d'execution." -ForegroundColor Green
        Write-Host "   [PROFIL ACTIF] : $($fwAudit.ActiveProfile)" -ForegroundColor Gray
    }

    # Details et recommandations RDP
    if ($fwAudit.RdpRuleDetails) {
        Write-Host "`n   Regles RDP detectees (nom / LocalAddress / RemoteAddress) :" -ForegroundColor Gray
        foreach ($r in $fwAudit.RdpRuleDetails) {
            Write-Host "      - $($r.Name)    Local: $($r.LocalAddress)    Remote: $($r.RemoteAddress)" -ForegroundColor Yellow
        }

        if ($fwAudit.RdpRecommendations) {
            Write-Host "`n   Recommandations RDP :" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) { Write-Host "      - $rec" -ForegroundColor Yellow }
        }
    }
    else {
        Write-Host "`n   [INFO] Aucune regle RDP activee detectee." -ForegroundColor Gray
        if ($fwAudit.RdpRecommendations -and ($fwAudit.RdpRecommendations | Measure-Object).Count -gt 0) {
            Write-Host "   Recommandation : $($fwAudit.RdpRecommendations -join '; ')" -ForegroundColor Yellow
        }
    }

    # Recommandations globales
    if ($fwAudit.GlobalRecommendations -and ($fwAudit.GlobalRecommendations | Measure-Object).Count -gt 0) {
        Write-Host "`n   Recommandations globales :" -ForegroundColor Yellow
        foreach ($g in $fwAudit.GlobalRecommendations) { Write-Host "      - $g" -ForegroundColor Yellow }
    }
}
else {
    Write-Error "Impossible d'auditer le pare-feu (Get-FirewallAudit n'a pas retourne de resultat)"
}

########## VPN Audit ##########
Write-Host "`n[+] Audit des connexions VPN :" -ForegroundColor Gray
$vpnStatus = Get-VPNStatus

if ($vpnStatus) {
    Write-Host "   Description : $($vpnStatus.Description)" -ForegroundColor Gray

    if ($vpnStatus.HasVpnAdapters) {
        Write-Host "`n   Interfaces VPN/TAP/TUN actives detectees :" -ForegroundColor Gray
        foreach ($a in $vpnStatus.Adapters) {
            Write-Host "      - $($a.Name) | $($a.InterfaceDescription) | $($a.Status)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [INFO] Aucune interface VPN/TAP/TUN active detectee." -ForegroundColor Gray
    }

    if ($vpnStatus.HasVpnProfiles) {
        Write-Host "`n   Profils VPN configures : $(($vpnStatus.VpnProfiles | Measure-Object).Count)" -ForegroundColor Gray
        if ($vpnStatus.HasActiveVpnProfiles) {
            Write-Host "   Profils VPN connectes : $(($vpnStatus.ActiveVpnProfiles | Measure-Object).Count)" -ForegroundColor Green
        } else {
            Write-Host "   Aucun profil VPN actuellement connecte." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [INFO] Aucun profil VPN configure via le client Windows." -ForegroundColor Gray
    }
} else {
    Write-Error "Impossible d'auditer le VPN (Get-VPNStatus n'a pas retourne de resultat)"
}

##########################################
#           OS Security Audit            #
##########################################

########## Optional Features Audit ##########

Write-Host "`n[+] Audit des fonctionnalites optionnelles (Windows Optional Features) :" -ForegroundColor Gray
try {
    $optFeatures = Get-OptionalFeaturesAudit

    if ($optFeatures) {
        Write-Host "   [INFO] Nombre de fonctionnalites optionnelles activees : $(($optFeatures | Measure-Object).Count)" -ForegroundColor Gray

        # Affichage synthetique
        $optFeatures |
            Select-Object FeatureName, State,
                @{Name='Risk';Expression={ if ($_.RiskNote) { $_.RiskNote } else { 'Aucun risque specifique detecte' } } },
                Recommendation |
            Sort-Object @{Expression={ if ($_.Risk -ne 'Aucun risque specifique detecte') { 0 } else { 1 } } }, FeatureName |
            Format-Table -AutoSize

        # Affichage detaille des elements a risque
        $risky = $optFeatures | Where-Object { $_.RiskNote -ne '' }
        if ($risky) {
            Write-Host "`n   [ATTENTION] Fonctions potentiellement dangereuses / exposees :" -ForegroundColor Yellow
            foreach ($f in $risky) {
                Write-Host "      - $($f.FeatureName) : $($f.RiskNote)" -ForegroundColor Yellow
                Write-Host "         Recommandation : $($f.Recommendation)" -ForegroundColor Yellow
                Write-Host "         Action suggeree (exemple) : Disable-WindowsOptionalFeature -Online -FeatureName `"$($f.FeatureName)`" -NoRestart" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "   [OK] Aucune fonctionnalite optionnelle notablement risquee detectee." -ForegroundColor Green
        }
    } else {
        Write-Host "   [INFO] Aucune fonctionnalite optionnelle activee detectee." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Erreur lors de l'audit des fonctionnalites optionnelles : $($_.Exception.Message)"
}


########## AppLocker Audit ##########

Write-Host "`n[+] Audit de la configuration AppLocker :" -ForegroundColor Gray
try {
    $appLockerState = Get-AppLockerState

    if ($appLockerState) {
        if ($appLockerState.AppLockerPresent) {
            # AppLocker est present
            if ($appLockerState.AnyRuleEnabled) {
                Write-Host "   [OK] AppLocker est present et au moins une collection de regles est en mode Enforced." -ForegroundColor Green
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Green
            } else {
                Write-Host "   [INFO] AppLocker est present mais aucune collection de regles n'est en mode Enforced." -ForegroundColor Yellow
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
            }
        } else {
            # Aucune politique AppLocker effective
            Write-Host "   [ALERTE] Aucune politique AppLocker effective detectee sur ce systeme." -ForegroundColor Red
            Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
        }

        # Affichage de la recommandation
        Write-Host "       Recommandation : $($appLockerState.Recommendation)" -ForegroundColor Yellow
    } else {
        Write-Error "Impossible d'auditer AppLocker (Get-AppLockerState n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-AppLockerState a echoue : $($_.Exception.Message)"
}


########## SRP Audit ##########

Write-Host "`n[+] Audit de la configuration SRP (Software Restriction Policies) :" -ForegroundColor Gray
try {
    $srpAudit = Get-SRPState

    if ($srpAudit) {
        foreach ($srp in $srpAudit) {
            Write-Host "`n   Scope: $($srp.Scope)" -ForegroundColor Cyan
            
            if ($srp.SRPPresent) {
                Write-Host "   [DETECTE] SRP est configure pour ce scope." -ForegroundColor Yellow
            } else {
                Write-Host "   [ABSENT] Aucune SRP detectee pour ce scope." -ForegroundColor Green
            }
            
            Write-Host "   Chemin du registre: $($srp.RegistryPath)" -ForegroundColor Gray
            Write-Host "   Statut: $($srp.Comment)" -ForegroundColor Gray
            Write-Host "   Recommandation: $($srp.Recommendation)" -ForegroundColor Yellow
        }
    } else {
        Write-Error "Impossible d'auditer SRP (Get-SRPState n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-SRPState a echoue : $($_.Exception.Message)"
}


########## Server Antivirus Status Audit ##########

Write-Host "`n[+] Audit de l'etat des services antivirus :" -ForegroundColor Gray
$antivirusStatus = Get-ServerAntivirusStatus

if ($antivirusStatus) {
    foreach ($av in $antivirusStatus) {
        Write-Host "`nService : $($av.Name)" -ForegroundColor Cyan
        
        if ($av.Present -eq $false) {
            Write-Host "   [ALERTE] Aucune solution antivirus detectee sur ce serveur." -ForegroundColor Red
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
        } else {
            # Statut du service
            if ($av.ServiceRunning) {
                Write-Host "   [OK] Le service antivirus est en cours d'execution." -ForegroundColor Green
            } else {
                Write-Host "   [ALERTE] Le service antivirus n'est pas en cours d'execution." -ForegroundColor Red
            }

            # Monitoring en temps reel (pour Defender uniquement)
            if ($null -ne $av.RealtimeMonitoring) {
                if ($av.RealtimeMonitoring) {
                    Write-Host "   [OK] La protection en temps reel est activee." -ForegroundColor Green
                } else {
                    Write-Host "   [ALERTE] La protection en temps reel est desactivee." -ForegroundColor Red
                }
            }

            # Status global
            if ($av.OverallProtected) {
                Write-Host "   [OK] Protection globale : Active" -ForegroundColor Green
            } else {
                Write-Host "   [ALERTE] Protection globale : Inactive ou degradee" -ForegroundColor Red
            }

            # Contexte serveur
            if ($av.IsDomainController) {
                Write-Host "   [INFO] Cette machine est un controleur de domaine." -ForegroundColor Magenta
            }

            # Description et recommandation
            Write-Host "   Description : $($av.Description)" -ForegroundColor Gray
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Error "Impossible d'auditer l'etat des services antivirus (Get-ServerAntivirusStatus n'a pas retourne de resultat)"
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
            Write-Host "   [ALERTE] Les hachs LM peuvent etre stockes sur ce systeme." -ForegroundColor Red
            Write-Host "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [OK] Les hachs LM ne sont pas stockes (NoLMHash = 1)." -ForegroundColor Green
            Write-Host "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
        }

        # Affichage des actions proposees
        if ($lmHashStatus.Xml) {
            Write-Host "`n   Action proposee :" -ForegroundColor Gray
            Write-Host "      - $($lmHashStatus.Xml.Category) : $($lmHashStatus.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($lmHashStatus.Xml.Command)" -ForegroundColor DarkGray
        }
    } else {
        Write-Error "Impossible d'auditer la configuration LM Hash (Get-LMHashStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-LMHashStatus a echoue : $($_.Exception.Message)"
}

########## LSA Authentication Level Audit ##########

Write-Host "`n[+] Audit du niveau d'authentification LSA (LmCompatibilityLevel) :" -ForegroundColor Gray
try {
    $lsaAuthLevel = Get-LsaAuthLevel

    if ($lsaAuthLevel -and $lsaAuthLevel.Value) {
        $lsa = $lsaAuthLevel.Value

        Write-Host "   Path: $($lsa.Path)" -ForegroundColor Gray
        Write-Host "   LmCompatibilityLevel: $($lsa.LmCompatibilityLevel)" -ForegroundColor Gray
        Write-Host "   Description: $($lsa.Description)" -ForegroundColor Gray

        # Evaluation basee sur la recommandation
        if ($lsa.Recommendation -match "^OK:") {
            Write-Host "   [OK] $($lsa.Recommendation)" -ForegroundColor Green
        } elseif ($lsa.Recommendation -match "Recommended") {
            Write-Host "   [RECOMMANDATION] $($lsa.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [INFO] $($lsa.Recommendation)" -ForegroundColor Gray
        }

        # Affichage des actions proposees si necessaire
        if ($lsaAuthLevel.Xml) {
            Write-Host "`n   Action proposee :" -ForegroundColor Gray
            Write-Host "      - $($lsaAuthLevel.Xml.Category) : $($lsaAuthLevel.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($lsaAuthLevel.Xml.Command)" -ForegroundColor DarkGray
        }
    } else {
        Write-Error "Impossible d'auditer le niveau d'authentification LSA (Get-LsaAuthLevel n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-LsaAuthLevel a echoue : $($_.Exception.Message)"
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
                Write-Host "   [OK] LSA protection activee (RunAsPPL = 2, Secure Boot requis)." -ForegroundColor Green
            }
            1 {
                Write-Host "   [OK] LSA protection activee (RunAsPPL = 1)." -ForegroundColor Green
            }
            default {
                Write-Host "   [ALERTE] LSA protection non activee ou valeur inconnue." -ForegroundColor Red
            }
        }

        Write-Host "   WDigest Path : $($p.WDigestPath)" -ForegroundColor Gray
        Write-Host "   UseLogonCredential : $($p.UseLogonCredential)" -ForegroundColor Gray

        if ($p.UseLogonCredential -eq 1) {
            Write-Host "   [ALERTE] WDigest active a€ mots de passe potentiellement stockes en clair dans LSASS." -ForegroundColor Red
            Write-Host "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        } else {
            Write-Host "   [OK] WDigest desactive ou valeur explicite presente." -ForegroundColor Green
            Write-Host "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        }

        if ($lsassAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $lsassAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Error "Impossible d'auditer LSASS (Get-LsassProtectionStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-LsassProtectionStatus a echoue : $($_.Exception.Message)"
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
            Write-Host "   [OK] Credential Guard active." -ForegroundColor Green
        } else {
            Write-Host "   [ALERTE] Credential Guard desactive ou non configure." -ForegroundColor Red
        }

        Write-Host "   TPM present    : $($cg.HasTPM)" -ForegroundColor Gray
        Write-Host "   SecureBoot     : $($cg.SecureBoot)" -ForegroundColor Gray
        Write-Host "   Virtualisation : $($cg.Virtualization)" -ForegroundColor Gray

        if (-not $cg.HasTPM -or -not $cg.SecureBoot -or -not $cg.Virtualization) {
            Write-Host "`n   [PREREQUIS MANQUANTS]" -ForegroundColor Yellow
            if (-not $cg.HasTPM)    { Write-Host "      - TPM manquant ou version non supportee." -ForegroundColor Yellow }
            if (-not $cg.SecureBoot){ Write-Host "      - Secure Boot non active." -ForegroundColor Yellow }
            if (-not $cg.Virtualization) { Write-Host "      - Virtualisation materielle non presente." -ForegroundColor Yellow }
            Write-Host "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Yellow
        } else {
            Write-Host "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Gray
        }
    }
    else {
        Write-Error "Impossible d'auditer Credential Guard (Get-CredentialGuardStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-CredentialGuardStatus a echoue : $($_.Exception.Message)"
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
            Write-Host "   [OK] Virtualization-Based Security (VBS) et/ou WDAC detecte(s)." -ForegroundColor Green
            Write-Host "   Recommandation : $($dg.Recommendation)" -ForegroundColor Gray

            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Audit') {
                Write-Host "   [INFO] WDAC en mode Audit a€ examiner les journaux et prevoir passage en Enforced si stable." -ForegroundColor Yellow
            }
            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Enforced') {
                Write-Host "   [OK] WDAC / Code Integrity en mode Enforced." -ForegroundColor Green
            }
        }
        else {
            Write-Host "   [ALERTE] Ni VBS ni WDAC actives sur ce systeme." -ForegroundColor Red
            Write-Host "   Recommandation : $($dg.Recommendation)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Error "Impossible d'auditer Device Guard (Get-DeviceGuardStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-DeviceGuardStatus a echoue : $($_.Exception.Message)"
}



########## Exploit Protection / Process Mitigations Audit ##########

Write-Host "`n[+] Audit Exploit Protection (Process Mitigations) :" -ForegroundColor Gray
try {
    $epAudit = Get-ExploitProtectionStatus

    if ($epAudit -and $epAudit.Value) {
        $ep = $epAudit.Value
        $issues = @()

        Write-Host "   DEP (Data Execution Prevention)            : $($ep.DEP_Enable)" -ForegroundColor Gray
        if (-not $ep.DEP_Enable) { $issues += 'DEP' ; Write-Host "      [ALERTE] DEP non active." -ForegroundColor Red } else { Write-Host "      [OK] DEP active." -ForegroundColor Green }

        Write-Host "   CFG (Control Flow Guard)                   : $($ep.CFG_Enable)" -ForegroundColor Gray
        if (-not $ep.CFG_Enable) { $issues += 'CFG' ; Write-Host "      [ALERTE] CFG non active." -ForegroundColor Red } else { Write-Host "      [OK] CFG active." -ForegroundColor Green }

        Write-Host "   SEHOP (SEH Overwrite Protection)          : $($ep.SEHOP_Enable)" -ForegroundColor Gray
        if (-not $ep.SEHOP_Enable) { $issues += 'SEHOP' ; Write-Host "      [ALERTE] SEHOP non active." -ForegroundColor Red } else { Write-Host "      [OK] SEHOP active." -ForegroundColor Green }

        Write-Host "   ASLR Bottom-Up                              : $($ep.ASLR_BottomUP)" -ForegroundColor Gray
        if (-not $ep.ASLR_BottomUP) { $issues += 'ASLR_BottomUP' ; Write-Host "      [ALERTE] ASLR Bottom-Up non active." -ForegroundColor Red } else { Write-Host "      [OK] ASLR Bottom-Up active." -ForegroundColor Green }

        Write-Host "   ASLR High-Entropy                           : $($ep.ASLR_HighEntropy)" -ForegroundColor Gray
        if (-not $ep.ASLR_HighEntropy) { $issues += 'ASLR_HighEntropy' ; Write-Host "      [ALERTE] ASLR High-Entropy non active." -ForegroundColor Red } else { Write-Host "      [OK] ASLR High-Entropy active." -ForegroundColor Green }

        Write-Host "   ASLR ForceRelocateImages                    : $($ep.ASLR_ForceRelocateImages)" -ForegroundColor Gray
        if (-not $ep.ASLR_ForceRelocateImages) { $issues += 'ASLR_ForceRelocateImages' ; Write-Host "      [ALERTE] ForceRelocateImages non active." -ForegroundColor Red } else { Write-Host "      [OK] ForceRelocateImages active." -ForegroundColor Green }

        Write-Host "`n   Synthese :" -ForegroundColor Gray
        if (($issues | Measure-Object).Count -eq 0) {
            Write-Host "      [OK] Parametres globaux d'Exploit Protection solides." -ForegroundColor Green
            Write-Host "      Recommandation : $($ep.Recommendation)" -ForegroundColor Gray
        } else {
            Write-Host "      [ALERTE] Parametres manquants ou desactives : $($issues -join ', ')" -ForegroundColor Red
            Write-Host "      Recommandation : $($ep.Recommendation)" -ForegroundColor Yellow
        }

        if ($epAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $epAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            }
        }
    }
    else {
        Write-Error "Impossible d'auditer Exploit Protection (Get-ExploitProtectionStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-ExploitProtectionStatus a echoue : $($_.Exception.Message)"
}


########## ASR (Attack Surface Reduction) Audit ##########

Write-Host "`n[+] Audit Attack Surface Reduction (ASR) :" -ForegroundColor Gray
try {
    $asrAudit = Get-ASRStatus

    if (-not $asrAudit) {
        Write-Error "Impossible d'auditer ASR (Get-ASRStatus n'a pas retourne de resultat)"
    }
    elseif ($asrAudit -is [System.Collections.IEnumerable] -and ($asrAudit | Where-Object { $_.RuleId })) {
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
        # Cas ou Get-ASRStatus renvoie un objet unique indiquant l'absence de regles
        Write-Host "   $($asrAudit.Comment)" -ForegroundColor Red
        Write-Host "   Recommandation : $($asrAudit.Recommendation)" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Get-ASRStatus a echoue : $($_.Exception.Message)"
}

########## Network Protection (Defender) Audit ##########

Write-Host "`n[+] Audit Network Protection (Microsoft Defender) :" -ForegroundColor Gray
try {
    $np = Get-NetworkProtectionStatus

    if ($np) {
        Write-Host "   Mode detecte : $($np.Mode)" -ForegroundColor Gray
        switch ($np.Mode) {
            'Block' {
                Write-Host "   [OK] Network Protection en mode Block." -ForegroundColor Green
            }
            'Audit' {
                Write-Host "   [INFO] Network Protection en mode Audit." -ForegroundColor Yellow
            }
            'Off' {
                Write-Host "   [ALERTE] Network Protection desactive." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Network Protection non configure." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($np.RawValue)" -ForegroundColor Yellow
            }
        }

        Write-Host "   EnableNetworkProtection : $($np.EnableNetworkProtection)" -ForegroundColor Gray
        Write-Host "`n   Recommandation : $($np.Recommendation)" -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Network Protection (Get-NetworkProtectionStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-NetworkProtectionStatus a echoue : $($_.Exception.Message)"
}


########## Controlled Folder Access (CFA) Audit ##########

Write-Host "`n[+] Audit Controlled Folder Access (Defender) :" -ForegroundColor Gray
try {
    $cfa = Get-ControlledFolderAccessStatus

    if ($cfa) {
        Write-Host "   Mode detecte : $($cfa.Mode)" -ForegroundColor Gray

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
                Write-Host "   [ALERTE] Controlled Folder Access desactive." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Controlled Folder Access non configure." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($cfa.EnableControlledFolderAccess)" -ForegroundColor Yellow
            }
        }

        Write-Host "`n   Recommandation : $($cfa.Recommendation)" -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Controlled Folder Access (Get-ControlledFolderAccessStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-ControlledFolderAccessStatus a echoue : $($_.Exception.Message)"
}


########## Smart App Control Audit ##########

Write-Host "`n[+] Audit Smart App Control :" -ForegroundColor Gray
try {
    $sac = Get-SmartAppControlStatus

    if ($sac) {
        Write-Host "   Smart App Control : $($sac.SmartApp_State)" -ForegroundColor Gray

        switch ($sac.SmartApp_State) {
            'On' {
                Write-Host "   [OK] Smart App Control active." -ForegroundColor Green
            }
            'Evaluation' {
                Write-Host "   [INFO] Smart App Control en mode Evaluation." -ForegroundColor Yellow
            }
            'Off' {
                Write-Host "   [ALERTE] Smart App Control desactive." -ForegroundColor Red
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Smart App Control non configure." -ForegroundColor Red
            }
            default {
                Write-Host "   [INCONNU] Valeur detectee : $($sac.SmartApp_State)" -ForegroundColor Yellow
            }
        }

        Write-Host "`n   Recommandation : Tester en mode Evaluation puis activer (On) sur systemes compatibles." -ForegroundColor Yellow
    }
    else {
        Write-Error "Impossible d'auditer Smart App Control (Get-SmartAppControlStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-SmartAppControlStatus a echoue : $($_.Exception.Message)"
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
        Write-Error "Impossible d'auditer le mode PowerShell (Get-PowerShellLanguageMode n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-PowerShellLanguageMode a echoue : $($_.Exception.Message)"
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
                Write-Host "      [ALERTE] Autorun potentiellement active." -ForegroundColor Red
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Yellow
            }
            else {
                Write-Host "      [OK] Autorun desactive pour ce scope." -ForegroundColor Green
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Gray
            }
        }

        if ($ar.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            Write-Host "      - $($ar.Xml.Category) : $($ar.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($ar.Xml.Command)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Error "Impossible d'auditer AutoRun (Get-AutorunStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-AutorunStatus a echoue : $($_.Exception.Message)"
}

########## BitLocker Audit ##########

Write-Host "`n[+] Audit BitLocker :" -ForegroundColor Gray
try {
    $bitlocker = Get-BitLockerAudit

    if ($bitlocker) {
        foreach ($vol in $bitlocker) {
            Write-Host "`n   Volume : $($vol.MountPoint) ($($vol.VolumeType))" -ForegroundColor Cyan
            Write-Host "      ProtectionStatus   : $($vol.ProtectionStatus)  |  Chiffrement : $($vol.EncryptionPercent)% " -ForegroundColor Gray
            if ($vol.ProtectionStatus -eq 'On' -and $vol.EncryptionPercent -ge 100) {
                Write-Host "      [OK] Volume chiffre et protege." -ForegroundColor Green
            }
            elseif ($vol.ProtectionStatus -eq 'Suspended') {
                Write-Host "      [INFO] Protection suspendue." -ForegroundColor Yellow
            }
            else {
                Write-Host "      [ALERTE] Volume non protege ou chiffrement incomplet." -ForegroundColor Red
            }

            Write-Host "      TPM : $($vol.HasTPM)    PIN : $($vol.HasPIN)    RecoveryKey : $($vol.HasRecoveryPassword)" -ForegroundColor Gray
            Write-Host "      Commentaire : $($vol.Comment)" -ForegroundColor Gray
            Write-Host "      Recommandation : $($vol.Recommendation)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Error "Impossible d'auditer BitLocker (Get-BitLockerAudit n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-BitLockerAudit a echoue : $($_.Exception.Message)"
}


########## Thirda€‘Party Full Disk Encryption Indicators ##########

Write-Host "`n[+] Audit indicateurs de chiffrement tiers :" -ForegroundColor Gray
try {
    $tpe = Get-ThirdPartyEncryptionIndicators

    if ($null -eq $tpe) {
        Write-Error "Get-ThirdPartyEncryptionIndicators n'a pas retourne de resultat"
    }
    elseif ($tpe -is [System.Collections.IEnumerable]) {
        foreach ($item in $tpe) {
            # Attendu : proprietes possibles Name, Present, Version, Details, Recommendation
            $name = $item.Name      -or 'ThirdPartyEncryption'
            $present = $item.Present -or $false
            Write-Host "`n   Solution : $name" -ForegroundColor Cyan
            Write-Host "      Present : $present" -ForegroundColor Gray

            if ($present) {
                Write-Host "      [INFO] Chiffrement tiers detecte : $name" -ForegroundColor Green
                if ($item.Version) { Write-Host "      Version : $($item.Version)" -ForegroundColor Gray }
                if ($item.Details) { Write-Host "      Details : $($item.Details)" -ForegroundColor Gray }
                if ($item.Recommendation) { Write-Host "      Recommandation : $($item.Recommendation)" -ForegroundColor Yellow }
            } else {
                Write-Host "      [OK] Aucun chiffrement tiers detecte pour cet item." -ForegroundColor Green
            }
        }
    }
    else {
        # Cas objet unique attendu avec proprietes HasThirdParty/Detected/Details/Recommendation
        $has = $tpe.HasThirdParty  -or $tpe.Detected -or $false
        Write-Host "   Indicateur chiffrement tiers detecte : $has" -ForegroundColor Gray
        if ($has) {
            Write-Host "   [INFO] Un chiffrement tiers semble present. Details : $($tpe.Details)" -ForegroundColor Green
            if ($tpe.Recommendation) { Write-Host "   Recommandation : $($tpe.Recommendation)" -ForegroundColor Yellow }
        } else {
            Write-Host "   [OK] Aucun chiffrement tiers detecte." -ForegroundColor Purple
        }
    }
}
catch {
    Write-Warning "Get-ThirdPartyEncryptionIndicators a echoue : $($_.Exception.Message)"
}


##########################################
#            Update Management           #
##########################################

########## Last Reboot / Uptime Audit ##########

Write-Host "`n[+] Audit du dernier redemarrage :" -ForegroundColor Gray
try {
    $lr = Get-LastReboot

    if ($lr) {
        Write-Host "   Role de la machine : $($lr.ComputerRole)" -ForegroundColor Gray
        Write-Host "   Dernier demarrage   : $($lr.LastBootTime)" -ForegroundColor Gray
        Write-Host "   Uptime              : $($lr.Uptime) (jours: $($lr.UptimeDays))" -ForegroundColor Gray
        Write-Host "   Seuil recommande    : $($lr.ThresholdDays) jours" -ForegroundColor Gray

        if ($lr.UptimeDays -gt $lr.ThresholdDays) {
            Write-Host "   [ALERTE] Uptime superieur au seuil ($($lr.ThresholdDays) jours)." -ForegroundColor Red
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Yellow
        }
        else {
            Write-Host "   [OK] Uptime dans la plage attendue." -ForegroundColor Green
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Gray
        }
    }
    else {
        Write-Error "Impossible d'auditer le dernier redemarrage (Get-LastReboot n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-LastReboot a echoue : $($_.Exception.Message)"
}

##########################################
#                Logging                 #
##########################################

########## Logging / Event Collection Audit ##########

Write-Host "`n[+] Audit des journaux et de la collecte d'evenements :" -ForegroundColor Gray
try {
    # 1) Logs locaux (taille / retention)
    $logs = Get-LogStatus
    if ($logs) {
        foreach ($l in $logs) {
            Write-Host "`n   Log : $($l.LogName)" -ForegroundColor Cyan
            if (-not $l.IsEnabled) {
                Write-Host "      [ALERTE] Desactive ou indisponible." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                continue
            }

            Write-Host "      Enregistres : $($l.RecordCount)  |  MaxSize : $($l.MaximumSizeMB) MB  |  Reco : $($l.RecoSizeMB) MB" -ForegroundColor Gray

            if ($l.IsSizeOK -eq $true) {
                Write-Host "      [OK] Taille du journal conforme." -ForegroundColor Green
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
            }
            elseif ($l.IsSizeOK -eq $false) {
                Write-Host "      [ALERTE] Taille du journal insuffisante." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
            }
            else {
                Write-Host "      [INFO] Aucune recommandation de taille definie." -ForegroundColor Yellow
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Error "Get-LogStatus n'a pas retourne de resultat."
    }

    # 2) Event Forwarding & Sysmon
    $ef = Get-EventForwardingStatus
    if ($ef) {
        foreach ($e in $ef) {
            Write-Host "`n   Source : $($e.Name)" -ForegroundColor Cyan
            Write-Host "      Active : $($e.IsEnabled)" -ForegroundColor Gray
            Write-Host "      Commentaire : $($e.Comment)" -ForegroundColor Gray
            Write-Host "      Recommendation : $($e.Recommendation)" -ForegroundColor Yellow
        }
    } else {
        Write-Warning "Get-EventForwardingStatus n'a pas retourne de resultat."
    }

    # 3) Recherche d'agents de logs / SIEM
    $agents = Get-LogAgentStatus
    if ($agents) {
        Write-Host "`n   Agents de collecte detectes :" -ForegroundColor Gray
        foreach ($a in $agents) {
            if ($a.IsLogAgent) {
                Write-Host "      - $($a.DisplayName) (version: $($a.DisplayVersion))" -ForegroundColor Green
                Write-Host "         Recommendation : $($a.Recommendation)" -ForegroundColor Gray
            } else {
                Write-Host "      - Aucun agent connu detecte sur l'entree (bruit possible)." -ForegroundColor Yellow
                Write-Host "         Commentaire : $($a.Comment)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "`n   [ALERTE] Aucun agent de collecte/SIEM detecte." -ForegroundColor Red
        Write-Host "      Recommendation : Installer/configurer un agent pour centraliser les logs." -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Audit Logging a echoue : $($_.Exception.Message)"
}


# --- Fin ---
Write-Host "`nAudit termine." -ForegroundColor Cyan






