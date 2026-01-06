# --- Configuration ---
$ErrorActionPreference = "Stop"
$ScriptPath = $PSScriptRoot
$ModulePath = Join-Path -Path $ScriptPath -ChildPath "Modules\AuditCore"

# --- Collection for remediation actions (XML export) ---
$remediationActions = @()

# --- Importation du Module ---
Write-Host "Chargement du module d'audit..." -ForegroundColor Cyan
if (Test-Path $ModulePath) {
    Import-Module -Name $ModulePath -Force
}
else {
    Write-Error "Le module AuditCore est introuvable dans $ModulePath"
    exit
}

# Initialize auditResults structure
$auditResults = @{
    HostContext = $null
    AccountSecurity = @{
        LocalAdminAccount = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LocalGuestAccount = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LAPS = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ADPasswordPolicy = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LocalPasswordPolicy = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        AuthentificationLevel = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        UAC = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        JEA = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LocalGroups = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        SMBShares = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        NTFS = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    ServicesAndApplications = @{
        RDP = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        WinRM = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        SMB = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        Updates = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        InstalledApplications = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    NetworkSecurity = @{
        IPv6 = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LLMNR = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        NetBIOS = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        Firewall = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        VPN = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    DeviceSecurity = @{
        AutoRun = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        BitLocker = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ThirdPartyEncryptionIndicators = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    OSSecurity = @{
        OptionalFeatures = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        AppLocker = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        SRP = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ServerAntivirusStatus = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LMHash = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LSASSProtection = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        CredentialGuard = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ExploitProtection = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ASR = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        NetworkProtection = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        ControlledFolderAccess = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        SmartAppControl = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        PowershellLanguageMode = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    Logging = @{
        LogStatus = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        EventForwardingStatus = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        LogAgentStatus = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
    UpdateManagement = @{
        LastReboot = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
        NTFS = @{status = ""; automatable = $false; recommendations = @(); comments = ""}
    }
}

$scriptStartDate = Get-Date -Format 'yyyyMMdd_HHmmss'

# --- Helper Function to Merge Audit Results ---
function Merge-AuditResults {
    param(
        [Parameter(Mandatory=$true)]
        $Section,
        
        [Parameter(Mandatory=$false)]
        $AuditData
    )
    
    try {
        if ($null -eq $AuditData) { return }
        
        # Handle hashtables (dynamic objects)
        if ($AuditData -is [System.Collections.IDictionary]) {
            foreach ($key in $AuditData.Keys) {
                if ($key -notmatch "recommendation") {
                    $value = $AuditData[$key]
                    if ($null -ne $value) {
                        $Section[$key] = $value
                    }
                }
            }
        }
        # Handle PSObjects
        else {
            $properties = $AuditData | Get-Member -MemberType Properties
            foreach ($prop in $properties) {
                $propName = $prop.Name
                if ($propName -notmatch "recommendation") {
                    $value = $AuditData.$propName
                    if ($null -ne $value) {
                        if ($Section -is [System.Collections.IDictionary]) {
                            $Section[$propName] = $value
                        } else {
                            if ($Section | Get-Member -Name $propName -ErrorAction SilentlyContinue) {
                                $Section.$propName = $value
                            } else {
                                $Section | Add-Member -MemberType NoteProperty -Name $propName -Value $value -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erreur lors de la fusion des resultats d'audit : $_"
    }
}

# --- Export Audit Results Function ---
function Export-AuditResultsToJson {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$AuditData,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = $PSScriptRoot,

        [Parameter(Mandatory=$false)]
        [string]$scriptStartDate,
        
        [Parameter(Mandatory=$false)]
        [int]$Depth = 10
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $jsonFile = Join-Path -Path $OutputPath -ChildPath "auditResults\auditResults_$scriptStartDate.json"
        
        $AuditData | ConvertTo-Json -Depth $Depth | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
        
        Write-Host "[✓] Resultats exportes : $jsonFile" -ForegroundColor Green
        return $jsonFile
    }
    catch {
        Write-Error "Erreur export JSON : $($_.Exception.Message)"
        return $null
    }
}

# --- Execution de l'Audit ---
Write-Host "Demarrage de l'audit sur $env:COMPUTERNAME..." -ForegroundColor Green

# 1. Recuperation du contexte (appel de notre fonction importee)
$context = Get-HostContext

$auditResults.HostContext = $context

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

$auditResults.AccountSecurity = @{}

########## Local User Audit ##########

$localUserAudit = Get-LocalUserAudit

if ($localUserAudit) {
    Write-Host "`n[+] Comptes locaux identifies :" -ForegroundColor Gray
    $auditResults.AccountSecurity.LocalAdminAccount = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }
    if (($localUserAudit.Value.AdminAccountSID -match "-500$") -and ($localUserAudit.Value.AdminEnabled -eq $true)){
        Write-Host "`nLe compte Administrateur par defaut est active" -ForegroundColor Red
        Write-Host $localUserAudit.Value.AdminRecommandation.Enabled -ForegroundColor Yellow
        $auditResults.AccountSecurity.LocalAdminAccount.status = "FAIL"
        $auditResults.AccountSecurity.LocalAdminAccount.recommendations += $localUserAudit.Value.AdminRecommandation.Enabled
        $auditResults.AccountSecurity.LocalAdminAccount.comments += "Administrator default account is enabled."     
    }
    else {
        Write-Host "$($localUserAudit.Value.AdminRecommandation.Disabled)" -ForegroundColor Green
        
        $auditResults.AccountSecurity.LocalAdminAccount.status = "PASS"
        $auditResults.AccountSecurity.LocalAdminAccount.recommendations += $localUserAudit.Value.AdminRecommandation.Disabled
        $auditResults.AccountSecurity.LocalAdminAccount.comments += "Administrator default account is disabled."
    }

    $auditResults.AccountSecurity.LocalGuestAccount = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }
    if (($localUserAudit.Value.GuestAccountSID -match "-501$") -and ($localUserAudit.Value.GuestEnabled -eq $true)){
        Write-Host "`nLe compte Invite par defaut est active" -ForegroundColor Red
        Write-Host $localUserAudit.Value.GuestRecommandation.Enabled -ForegroundColor Yellow
        $auditResults.AccountSecurity.LocalGuestAccount.status = "FAIL"
        $auditResults.AccountSecurity.LocalGuestAccount.recommendations += $localUserAudit.Value.GuestRecommandation.Enabled
        $auditResults.AccountSecurity.LocalGuestAccount.comments += "Guest default account is enabled."

    } else {
        Write-Host $localUserAudit.Value.GuestRecommandation.Disabled -ForegroundColor Green
        $auditResults.AccountSecurity.LocalGuestAccount.status = "PASS"
        $auditResults.AccountSecurity.LocalGuestAccount.recommendations += $localUserAudit.Value.GuestRecommandation.Disabled
        $auditResults.AccountSecurity.LocalGuestAccount.comments += "Guest default account is disabled."
    }
}
else {
    Write-Error "Impossible d'auditer les utilisateurs locaux"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.LocalAdminAccount -AuditData $localUserAudit
Merge-AuditResults -Section $auditResults.AccountSecurity.LocalGuestAccount -AuditData $localUserAudit

########## Privilege Audit ##########

$privilegeAudits = Get-Privilege

foreach ($audit in $privilegeAudits) {
    Write-Host "`n[+] Audit du privilege $($audit.Privilege) :" -ForegroundColor Gray
    $auditResults.AccountSecurity.Privilege = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }
    $auditResults.AccountSecurity.Privilege.recommendations += $audit.Recommendation
    if ($audit.Configured) {
        Write-Host "Privilege configure : $($audit.Privilege)" -ForegroundColor Yellow
        Write-Host "Assigne a : $($audit.AssignedTo -join ', ')" -ForegroundColor Gray
        Write-Host "Administrateurs presents : $($audit.IsAdminPresent)" -ForegroundColor Gray
        Write-Host "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
        $auditResults.AccountSecurity.Privilege.status = "WARNING"
        $auditResults.AccountSecurity.Privilege.comments += "Privilege $($audit.Privilege), assigned to $($audit.AssignedTo -join ', '). Admins present: $($audit.IsAdminPresent)."
    } else {
        Write-Host "Privilege non configure." -ForegroundColor Green
        Write-Host "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
        $auditResults.AccountSecurity.Privilege.status = "PASS"
        $auditResults.AccountSecurity.Privilege.comments += "Privilege $($audit.Privilege) is not configured."

    }
}
Merge-AuditResults -Section $auditResults.AccountSecurity.Privilege -AuditData $audit



########## LAPS Audit ##########
$auditResults.AccountSecurity.LAPS = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

$lapsAudit = Get-LAPSAudit
Write-Host "`n[+] Audit de la configuration LAPS :" -Foregroundcolor Gray

if ($lapsaudit){

    if ($context.Domainjoined -eq $true) {
        $auditResults.AccountSecurity.LAPS.recommendations += $lapsAudit.Recommendation

        # Affichage dynamique selon le resultat
        switch ($lapsAudit.Status) {
            "PASS" {
                Write-Host "   [OK] $($lapsAudit.DetectedMethods)" -ForegroundColor Green
                # Si on a un warning mineur (ex: Legacy + Modern en meme temps)
                if ($lapsAudit.Recommendation -match "ATTENTION") {
                    Write-Host "   $($lapsAudit.Recommendation)" -ForegroundColor Magenta
                }
                $auditResults.AccountSecurity.LAPS.status = "PASS"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS configuration is compliant."
            }
            "WARNING" {
                # Cas specifique Legacy seul
                Write-Host "   [OBSOLETE] $($lapsAudit.DetectedMethods)" -ForegroundColor Orange
                Write-Host "   -> $($lapsAudit.Recommendation)" -ForegroundColor Yellow
                $auditResults.AccountSecurity.LAPS.status = "WARNING"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS configuration uses obsolete methods."
            }
            "FAIL" {
                Write-Host "   [ALERTE] $($lapsAudit.Recommendation)" -ForegroundColor Red
                $auditResults.AccountSecurity.LAPS.status = "FAIL"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS is not configured."
            }
        }

    }
    else {
        Write-Host "`rLa machine n'est pas jointe a un domaine. LAPS n'est pas auditable" -ForegroundColor Magenta
    }
}

Merge-AuditResults -Section $auditResults.AccountSecurity.LAPS -AuditData $lapsAudit

########## Active Directory Password Policy Audit ##########
$auditResults.AccountSecurity.ADPasswordPolicy = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

if ($context.Domainjoined -eq $true){
    $auditResults.AccountSecurity.ADPasswordPolicy = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    $adPasswordPolicy = Get-ADPolPassAudit

    if ($adPasswordPolicy -and $context.Domainjoined -eq $true) {
        $auditResults.AccountSecurity.ADPasswordPolicy.status = "PASS"

        Write-Host "`n[+] Audit des politiques de mots de passe Active Directory :" -Foregroundcolor Gray
        try {
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Password Policy length must be at least $($adPasswordPolicy.MinLengthReco)"
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Password Complexity must be $($adPasswordPolicy.ComplexityReco)"
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Account Lockout Policy must be $($adPasswordPolicy.LockoutReco)"
                
            # Affichage Longueur
            if ($adPasswordPolicy.MinLengthStatus -eq "FAIL") {
                Write-Host "   [LONGUEUR]   [ALERTE] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password length requirement is not met."
            } else {
                Write-Host "   [LONGUEUR]   [OK] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password length requirement is met."
            }

            # Affichage Complexite
            if ($adPasswordPolicy.ComplexityStatus -eq "FAIL") {
                Write-Host "   [COMPLEXITE] [ALERTE] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password complexity requirement is not met."
            } else {
                Write-Host "   [COMPLEXITE] [OK] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password complexity requirement is met."
            }

            # Affichage Verrouillage
            if ($adPasswordPolicy.LockoutStatus -eq "FAIL") {
                Write-Host "   [BLOCAGE]    [ALERTE] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is not met."
            } elseif ($adPasswordPolicy.LockoutStatus -eq "WARNING") {
                Write-Host "   [BLOCAGE]    [MOYEN] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Magenta
                if ($auditResults.AccountSecurity.ADPasswordPolicy.status -ne "FAIL") {
                    $auditResults.AccountSecurity.ADPasswordPolicy.status = "WARNING"
                }
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is partially met."
            } else {
                Write-Host "   [BLOCAGE]    [OK] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is met."
            }
        }
        catch {
            Write-Host "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe AD"
        }
    }
    Merge-AuditResults -Section $auditResults.AccountSecurity.ADPasswordPolicy -AuditData $adPasswordPolicy
} else {
    ########## Local Password Policy Audit ##########
    $auditResults.AccountSecurity.LocalPasswordPolicy = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    Write-Host "`n[+] Audit des politiques de mots de passe :" -Foregroundcolor Gray

    
    try {
        $passwordPolicy = Get-PolPassAudit

        if ($passwordPolicy){
            $auditResults.AccountSecurity.LocalPasswordPolicy.status = "PASS"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Password Policy length must be at least $($passwordPolicy.MinLengthReco)"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Password Complexity must be $($passwordPolicy.ComplexityReco)"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Account Lockout Policy must be $($passwordPolicy.LockoutReco)"
                
            # Affichage Longueur
            if ($passwordPolicy.MinLengthStatus -eq "FAIL") {
                Write-Host "   [LONGUEUR]   [ALERTE] $($passwordPolicy.MinLengthReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password length requirement is not met."
            } else {
                Write-Host "   [LONGUEUR]   [OK] $($passwordPolicy.MinLengthReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password length requirement is met."
            }

            # Affichage Complexite
            if ($passwordPolicy.ComplexityStatus -eq "FAIL") {
                Write-Host "   [COMPLEXITE] [ALERTE] $($passwordPolicy.ComplexityReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password complexity requirement is not met."
            } else {
                Write-Host "   [COMPLEXITE] [OK] $($passwordPolicy.ComplexityReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password complexity requirement is met."
            }

            # Affichage Verrouillage
            if ($passwordPolicy.LockoutStatus -eq "FAIL") {
                Write-Host "   [BLOCAGE]    [ALERTE] $($passwordPolicy.LockoutReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is not met."
            } elseif ($passwordPolicy.LockoutStatus -eq "WARNING") {
                Write-Host "   [BLOCAGE]    [MOYEN] $($passwordPolicy.LockoutReco)" -ForegroundColor Magenta
                if ($auditResults.AccountSecurity.LocalPasswordPolicy.status -ne "FAIL") {
                    $auditResults.AccountSecurity.LocalPasswordPolicy.status = "WARNING"
                }
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is partially met."
            } else {
                Write-Host "   [BLOCAGE]    [OK] $($passwordPolicy.LockoutReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is met."
            }
        }
        
    } catch {
        Write-Host "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe"
    }
    
    Merge-AuditResults -Section $auditResults.AccountSecurity.LocalPasswordPolicy -AuditData $passwordPolicy
}



########## Authentication Level Audit ##########
$auditResults.AccountSecurity.AuthentificationLevel = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit du niveau d'authentification :" -Foregroundcolor Gray
$authLevelAudit = Get-AuthenticationLevelAudit

if ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $true) {
    $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Enable Windows Hello for Business via GPO or CSP."

    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via GPO."
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via CSP."
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is not enabled."
    }
} elseif ($context.osRole -eq "Workstation" -and $context.Domainjoined -eq $false) {
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Consider using Windows Hello for Business in a domain-joined environment."

    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [OK] Windows Hello (Consumer/Local) est active." -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is enabled."
    } else {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is not enabled."
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $true) {
    $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Enable Windows Hello for Business via GPO or CSP."

    if ($authLevelAudit.GPO -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via GPO."
    }
    if ($authLevelAudit.CSP -eq $true) {
        Write-Host "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via CSP."
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Write-Host "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is not enabled."
    }
} elseif ($context.osRole -eq "Server" -and $context.Domainjoined -eq $false) {
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Disable Windows Hello (Consumer/Local) on servers."

    if ($authLevelAudit.Consumer -eq $true) {
        Write-Host "   [ALERTE] Windows Hello (Consumer/Local) est active. Il est plutot recommande de desactiver cette fonctionnalite sur les serveurs." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is enabled on a server."
    } else {
        Write-Host "   [OK] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is not enabled on the server."
    }
} else {
    Write-Host "   [INFORMATION] Le niveau d'authentification n'a pas pu etre audite dans ce contexte." -ForegroundColor Yellow
}

Merge-AuditResults -Section $auditResults.AccountSecurity.AuthentificationLevel -AuditData $authLevelAudit

########## UAC Audit ##########
$auditResults.AccountSecurity.UAC = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration de l'UAC :" -Foregroundcolor Gray
$uacAudit = Get-UACAudit

try {
    $auditResults.AccountSecurity.UAC.status = "PASS"
    $auditResults.AccountSecurity.UAC.recommendations += "Enable UAC to enhance security."
    $auditResults.AccountSecurity.UAC.recommendations += "Enable Administrator Token Filtering to enhance security."
    $auditResults.AccountSecurity.UAC.recommendations += "Enable Local Account Token Filter Policy to prevent non-administrator network access."

    if ($uacAudit.UACEnabled -eq 1) {
        Write-Host "   [OK] L'UAC est active." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "UAC is enabled."
    } else {
        Write-Host "   [ALERTE] L'UAC est desactive." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "UAC is disabled."
    }

    if ($uacAudit.FilterAdministratorToken -eq 1) {
        Write-Host "   [OK] Le filtrage du token administrateur est active." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "Administrator Token Filtering is enabled."
    } else {
        Write-Host "   [ALERTE] Le filtrage du token administrateur est desactive." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "Administrator Token Filtering is disabled." 
    }

    if ($uacAudit.LocalAccountTokenFilterPolicy -eq 1) {
        Write-Host "   [OK] La politique de filtrage des tokens pour les comptes locaux est activee." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "Local Account Token Filter Policy is enabled."
    } else {
        Write-Host "   [OK] La politique de filtrage des tokens pour les comptes locaux est desactivee." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "Local Account Token Filter Policy is disabled."
    }
}
catch {
    Write-Host "Erreur lors de l'affichage des resultats de l'audit UAC"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.UAC -AuditData $uacAudit


########## JEA Audit ##########
$auditResults.AccountSecurity.JEA = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration JEA :" -Foregroundcolor Gray
$JEAAudit = Get-JEAAudit
try {
    $auditResults.AccountSecurity.JEA.recommendations += $JEAAudit.Recommandation

    if ($JEAAudit.WinRmState -eq 'NotInstalled'){
        Write-Host "   [INFORMATION] WinRM n'est pas installe. JEA ne peut pas etre configure." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.comments += "WinRM is not installed; JEA cannot be used."
    } elseif ($JEAAudit.WinRmState -eq 'Stopped') {
        Write-Host "   [ALERTE] WinRM est installe mais arrete. JEA ne peut pas etre utilise tant que WinRM n'est pas demarre." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.status = "FAIL"
        $auditResults.AccountSecurity.JEA.comments += "WinRM is stopped; JEA cannot be used."
    } elseif ($JEAAudit.HasJEASessionConfig -eq $true){
        Write-Host "   [OK] Des endpoints JEA sont configures sur cette machine." -ForegroundColor Green
        Write-Host "       $($JEAAudit.Recommandation)" -ForegroundColor Gray
        $auditResults.AccountSecurity.JEA.status = "PASS"
        $auditResults.AccountSecurity.JEA.comments += "JEA endpoints are configured."
    } elseif ($JEAAudit.HasJEASessionConfig -eq $false){
        Write-Host "   [ALERTE] WinRM est fonctionnel mais aucun endpoint JEA n'est configure." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.status = "FAIL"
        $auditResults.AccountSecurity.JEA.comments += "WinRM is running; No JEA endpoints are configured."
    } else {
        Write-Error "   [ERREUR] Impossible d'auditer la configuration JEA." -ForegroundColor Red
    }
} catch {
    Write-Host "Erreur lors de l'affichage des resultats de l'audit JEA"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.JEA -AuditData $JEAAudit


########## Local Groups Audit ##########
$auditResults.AccountSecurity.LocalGroups = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}
Write-Host "`n[+] Audit des groupes locaux :" -Foregroundcolor Gray
$groupsAudit = Get-GroupsAudit

if ($groupsAudit) {
    $auditResults.AccountSecurity.LocalGroups.status = "PASS"
    $auditResults.AccountSecurity.LocalGroups.recommendations += "A group should have at least one member. Verify local groups that have more than 3 members. Verify for unauthorized users."

    foreach ($group in $groupsAudit) {
        Write-Host "`nGroupe : $($group.GroupName)" -ForegroundColor Cyan
        if ($group.Members -eq 0) {
            Write-Host "   Aucun membre dans ce groupe." -ForegroundColor Yellow
            $auditResults.AccountSecurity.LocalGroups.status = "WARNING"
            $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has no members. Add complexity and increase attack surface."
        } else {
            Write-Host "   Membres : $($group.Members -join ', ')" -ForegroundColor Yellow
            # A voir je trouve que c'est un peu trop restreint comme alerte
            if ($group.MembersCount -gt 1) {
                Write-Host "   [ALERTE] Ce groupe contient un grand nombre de membres ($($group.MembersCount)). Verifiez qu'il n'y a pas d'utilisateurs non autorises." -ForegroundColor Red
                $auditResults.AccountSecurity.LocalGroups.status = "WARNING"
                $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has $($group.MembersCount) members. Verify for unauthorized users."
            } else {
                Write-Host "   [OK] Nombre de membres dans ce groupe : $($group.MembersCount)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has an acceptable number of members."
            }
        }
    }
} else {
    Write-Error "Impossible d'auditer les groupes locaux"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.LocalGroups -AuditData $groupsAudit

########## SMB Shares Audit ##########
$auditResults.AccountSecurity.SMBShares = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit des partages SMB :" -Foregroundcolor Gray
$smbSharesAudit = Get-SMBSharesAudit

Merge-AuditResults -Section $auditResults.AccountSecurity.SMBShares -AuditData $smbSharesAudit

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10
######################################
#    Service & Application Audits    #
######################################
$auditResults.ServicesAndApplications = @{}


########## RDP Audit ##########
$auditResults.ServicesAndApplications.RDP = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}
Write-Host "`n[+] Audit des services RDP :" -ForegroundColor Gray
$rdpAudit = Get-RDPAudit

if ($rdpAudit -and $rdpAudit.Value) {
    $r = $rdpAudit.Value

    if ($r.RDPEnabled -eq $true) {
        Write-Host "   [ENABLED] RDP est active sur cette machine." -ForegroundColor Red
        $auditResults.ServicesAndApplications.RDP.status = "FAIL"
        $auditResults.ServicesAndApplications.RDP.comments += "RDP is enabled."
    }
    else {
        Write-Host "   [DISABLED] RDP est desactive au niveau OS." -ForegroundColor Green
        $auditResults.ServicesAndApplications.RDP.status = "PASS"
        $auditResults.ServicesAndApplications.RDP.comments += "RDP is disabled. "
    }

    Write-Host "   [ADMIN RESTREINT] DisableRestrictedAdmin : $($r.DisableRestrictedAdmin)" -ForegroundColor Gray
    Write-Host "   [CHIFFREMENT] MinEncryptionLevel : $($r.MinEncryptionLevel)" -ForegroundColor Gray
    Write-Host "   [COUCHE DE SECURITE] SecurityLayer : $($r.SecurityLayer)" -ForegroundColor Gray
    Write-Host "   [NLA] UserAuthentication : $($r.UserAuthentication)" -ForegroundColor Gray

    if ($r.fEncryptRPCTraffic -eq $true) {
        Write-Host "   [RPC] fEncryptRPCTraffic : Enabled" -ForegroundColor Green
        $auditResults.ServicesAndApplications.RDP.comments += "RPC traffic encryption is enabled. "
    } else {
        Write-Host "   [RPC] fEncryptRPCTraffic : Disabled" -ForegroundColor Red
        $auditResults.ServicesAndApplications.RDP.comments += "RPC traffic encryption is disabled. "
        if ($auditResults.ServicesAndApplications.RDP.status -ne "FAIL") {
            $auditResults.ServicesAndApplications.RDP.status = "WARNING"
        }
    }

    if ($r.Recommendation) {
        Write-Host "`n   Recommandation : $($r.Recommendation)" -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.RDP.recommendations += "$($r.Recommendation) | "
    }

    if ($rdpAudit.Xml) {
        Write-Host "`n   Actions proposees :" -ForegroundColor Gray
        foreach ($item in $rdpAudit.Xml) {
            Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
            $auditResults.ServicesAndApplications.RDP.automatable = $true
            $remediationActions += $item
        }

    }

} else {
    Write-Error "Impossible d'auditer RDP (Get-RDPAudit n'a pas retourne de resultat)"
    $auditResults.ServicesAndApplications.RDP.status = "WARNING"
}

Merge-AuditResults -Section $auditResults.ServicesAndApplications.RDP -AuditData $rdpAudit


########## WinRM Audit ##########

$auditResults.ServicesAndApplications.WinRM = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit WinRM :" -ForegroundColor Gray
try {
    $winrmAudit = Get-WinRMAudit

    if (-not $winrmAudit.WinRmEnabled) {
        Write-Host "   [INACTIF] WinRM n'est pas installe ou le service est arrete." -ForegroundColor Magenta
        Write-Host "   Recommandation :" -ForegroundColor Yellow
        foreach ($r in $winrmAudit.Recommendations) { 
            Write-Host "      - $r" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.WinRM.recommendations += "$r | "
        }
        $auditResults.ServicesAndApplications.WinRM.status = "FAIL"
        $auditResults.ServicesAndApplications.WinRM.comments += "WinRM is not enabled. "
    }
    else {
        Write-Host "   [ACTIF] WinRM est active." -ForegroundColor Yellow
        Write-Host "   [TRANSPORT] ListenerTransport : $($winrmAudit.ListenerTransport)" -ForegroundColor Gray
        Write-Host "   [ECOUTE] ListeningOn        : $($winrmAudit.ListeningOn)" -ForegroundColor Gray
        Write-Host "   [FILTRES IP] IPv4 : $($winrmAudit.IPv4Filter)    IPv6 : $($winrmAudit.IPv6Filter)" -ForegroundColor Gray
        
        $auditResults.ServicesAndApplications.WinRM.status = "PASS"
        $auditResults.ServicesAndApplications.WinRM.comments += "WinRM is enabled. "

        if ($winrmAudit.ServiceAuth) {
            Write-Host "   [AUTH SERVICE] Basic : $($winrmAudit.ServiceAuth.Basic)    Unencrypted : $($winrmAudit.ServiceAuth.Unencrypted)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.WinRM.comments += "Service Auth Basic: $($winrmAudit.ServiceAuth.Basic), Unencrypted: $($winrmAudit.ServiceAuth.Unencrypted). "
        }
        if ($winrmAudit.ClientAuth) {
            Write-Host "   [AUTH CLIENT]  Basic : $($winrmAudit.ClientAuth.Basic)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.WinRM.comments += "Client Auth Basic: $($winrmAudit.ClientAuth.Basic). "
        }

        if ($winrmAudit.RmUsersNotAdmins) {
            Write-Host "   [UTILISATEURS] Comptes dans Remote Management Users (non-admin) : $($winrmAudit.RmUsersNotAdmins -join ', ')" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.WinRM.comments += "Non-admin Remote Management Users: $($winrmAudit.RmUsersNotAdmins -join ', '). "
        }

        if ($winrmAudit.Recommendations) {
            Write-Host "`n   Recommandations :" -ForegroundColor Yellow
            foreach ($rec in $winrmAudit.Recommendations) {
                Write-Host "      - $rec" -ForegroundColor Yellow
                $auditResults.ServicesAndApplications.WinRM.recommendations += "$rec | "
            }
        } else {
            Write-Host "   [OK] Configuration WinRM conforme aux bonnes pratiques detectee." -ForegroundColor Green
            $auditResults.ServicesAndApplications.WinRM.comments += "WinRM configuration complies with best practices. "
        }
    }
    Merge-AuditResults -Section $auditResults.ServicesAndApplications.WinRM -AuditData $winrmAudit
}
catch {
    Write-Warning "Get-WinRMAudit a echoue : $($_.Exception.Message)"
    $auditResults.ServicesAndApplications.WinRM.status = "WARNING"
    $auditResults.ServicesAndApplications.WinRM.comments += "Error auditing WinRM: $($_.Exception.Message). "
}



########## SMB Audit ##########

$auditResults.ServicesAndApplications.SMB = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}
Write-Host "`n[+] Audit SMB :" -ForegroundColor Gray

try {
    $smbAudit = Get-SMBAudit

    if ($smbAudit -and $smbAudit.Value) {
        $s = $smbAudit.Value
        $smbOk = $true

        # Affichage du statut SMBv1
        if ($s.SMBv1State -eq $true) {
            Write-Host "   [SMBv1] [ALERTE] SMBv1 est active. Il est recommande de le desactiver." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv1 is enabled. "
            $smbOk = $false
        } else {
            Write-Host "   [SMBv1] [OK] SMBv1 est desactive." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv1 is disabled. "
        }

        # Affichage du statut SMBv2/3
        if ($s.SMBv2State -eq $true) {
            Write-Host "   [SMBv2/3] [OK] SMBv2/3 est active." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv2/3 is enabled. "
        } else {
            Write-Host "   [SMBv2/3] [ALERTE] SMBv2/3 est desactive." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv2/3 is disabled. "
            $smbOk = $false
        }

        # Affichage du statut de la signature SMB
        if ($s.RequireSecuritySignature -eq $true) {
            Write-Host "   [SIGNING] [OK] La signature de securite SMB est requise." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMB signing is required. "
        } else {
            Write-Host "   [SIGNING] [ALERTE] La signature de securite SMB n'est pas requise." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMB signing is not required. "
            $smbOk = $false
        }

        if ($s.Comment) {
            Write-Host "`n   Details : $($s.Comment)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.SMB.comments += "$($s.Comment) "
        }

        if ($s.Recommendation) {
            Write-Host "`n   Recommandation : $($s.Recommendation)" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.SMB.recommendations += "$($s.Recommendation) | "
        }

        # Affichage des actions proposees
        if ($smbAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $smbAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
                $auditResults.ServicesAndApplications.SMB.automatable = $true
                $remediationActions += $item
            }
        }

        $auditResults.ServicesAndApplications.SMB.status = if ($smbOk) { "PASS" } else { "FAIL" }
    } else {
        Write-Error "Impossible d'auditer SMB (Get-SMBAudit n'a pas retourne de resultat)"
        $auditResults.ServicesAndApplications.SMB.status = "WARNING"
    }
    
    Merge-AuditResults -Section $auditResults.ServicesAndApplications.SMB -AuditData $smbAudit
}
catch {
    Write-Warning "Get-SMBAudit a echoue : $($_.Exception.Message)"
    $auditResults.ServicesAndApplications.SMB.status = "WARNING"
    $auditResults.ServicesAndApplications.SMB.comments += "Error auditing SMB: $($_.Exception.Message). "
}



########### Update Audit ##########

$auditResults.ServicesAndApplications.Updates = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit des mises a jour et version OS :" -ForegroundColor Gray
try {
    $osInfo = Get-OSVersionInfo
    if ($osInfo) {
        Write-Host "`n[OS] $($osInfo.Caption) - Version $($osInfo.Version) (Full: $($osInfo.FullVersion))" -ForegroundColor Cyan
        $auditResults.ServicesAndApplications.Updates.comments += "OS: $($osInfo.Caption), Version: $($osInfo.Version). "
        
        if ($osInfo.InstallDate) {
            $installDate = [datetime]$osInfo.InstallDate
            Write-Host "Build: $($osInfo.BuildNumber)   Installe le: $($installDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.Updates.comments += "Build: $($osInfo.BuildNumber), Installed: $($installDate.ToString('yyyy-MM-dd HH:mm')). "
        } else {
            Write-Host "Build: $($osInfo.BuildNumber)   InstallDate: Non disponible" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.Updates.comments += "Build: $($osInfo.BuildNumber). "
        }
        
        $auditResults.ServicesAndApplications.Updates.status = "PASS"
        $auditResults.ServicesAndApplications.Updates.recommendations += "Keep the system updated with latest security patches. "
    }

    $updateSource = Get-UpdateSource
    Write-Host "`n[Source de mises a jour] $updateSource" -ForegroundColor Gray
    $auditResults.ServicesAndApplications.Updates.comments += "Update source: $updateSource. "

    $kbList = Get-InstalledKB
    if ($kbList) {
        Write-Host "`n[+] Dernieres mises a jour installees (10 dernieres) :" -ForegroundColor Gray
        $kbList | Select-Object -First 10 | Format-Table HotFixID, Description, @{Name='InstalledOn';Expression={ ($_.InstalledOn -as [datetime]).ToString('yyyy-MM-dd') }}, InstalledBy -AutoSize
        $auditResults.ServicesAndApplications.Updates.comments += "$($kbList.Count) KB updates found. "
    } else {
        Write-Host "Aucune mise a jour detectee via Get-HotFix" -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.Updates.comments += "No updates found via Get-HotFix. "
        $auditResults.ServicesAndApplications.Updates.status = "WARNING"
    }
    Merge-AuditResults -Section $auditResults.ServicesAndApplications.Updates -AuditData $osInfo
}
catch {
    Write-Warning "Erreur lors de la collecte des informations de mise a jour : $($_.Exception.Message)"
    $auditResults.ServicesAndApplications.Updates.status = "WARNING"
    $auditResults.ServicesAndApplications.Updates.comments += "Error collecting update information: $($_.Exception.Message). "
}


########## Installed Applications Audit ##########

$auditResults.ServicesAndApplications.InstalledApplications = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit des applications installees :" -ForegroundColor Gray
try {
    $apps = Get-InstalledApplications

    if ($apps) {
        Write-Host "   [INFO] Nombre d'applications detectees : $(($apps | Measure-Object).Count)" -ForegroundColor Gray
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "$($apps.Count) applications detected. "
        $apps | Select-Object Name, Version, Publisher, InstallLocation |
            Sort-Object Name |
            Format-Table -AutoSize
        $auditResults.ServicesAndApplications.InstalledApplications.status = "PASS"
    } else {
        Write-Host "   [INFO] Aucune application installee detectee." -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "No installed applications detected. "
        $auditResults.ServicesAndApplications.InstalledApplications.status = "PASS"
    }

    # Verification des mises a jour applicatives via WinGet (si disponible)
    $appUpgrades = Get-AppUpgrade -ErrorAction SilentlyContinue
    if ($appUpgrades) {
        Write-Host "`n   [Mises a jour disponibles via WinGet] :" -ForegroundColor Yellow
        $appUpgrades |
            Select-Object Name, InstalledVersion, @{Name='Available';Expression={$_.AvailableVersions -join ','}} |
            Format-Table -AutoSize
        Write-Host "   Recommandation : utiliser `winget upgrade --all` pour mettre a jour les applications prises en charge." -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.InstalledApplications.recommendations += "Use 'winget upgrade --all' to update supported applications. "
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "$($appUpgrades.Count) application updates available via WinGet. "
        $auditResults.ServicesAndApplications.InstalledApplications.status = "WARNING"
    } elseif ($null -eq $appUpgrades) {
        Write-Host "   [INFO] WinGet non disponible ou aucune donnee de mise a jour." -ForegroundColor Gray
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "WinGet not available or no update data. "
    } else {
        Write-Host "   [OK] Aucune mise a jour applicative detectee via WinGet." -ForegroundColor Green
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "No application updates available via WinGet. "
        $auditResults.ServicesAndApplications.InstalledApplications.recommendations += "Applications are up to date. "
    }
    
    if ([string]::IsNullOrWhiteSpace($auditResults.ServicesAndApplications.InstalledApplications.status)) {
        $auditResults.ServicesAndApplications.InstalledApplications.status = "PASS"
    }
    Merge-AuditResults -Section $auditResults.ServicesAndApplications.InstalledApplications -AuditData $apps
}
catch {
    Write-Warning "Erreur lors de l'audit des applications installees : $($_.Exception.Message)"
    $auditResults.ServicesAndApplications.InstalledApplications.status = "WARNING"
    $auditResults.ServicesAndApplications.InstalledApplications.comments += "Error auditing installed applications: $($_.Exception.Message). "
}

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10

######################################
#      Network Security Audits       #
######################################
$auditResults.NetworkSecurity = @{}
########## IPv6 Audit ##########

$auditResults.NetworkSecurity.IPv6 = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration IPv6 :" -ForegroundColor Gray
$ipv6Audit = Get-IPv6Status

if ($ipv6Audit -and $ipv6Audit.Count -gt 0) {
    $auditResults.NetworkSecurity.IPv6.status = "PASS"
    $ipv6Recs = @()
    foreach ($adapter in $ipv6Audit) {
        if ($adapter.IPv6Enabled -eq $true) {
            Write-Host "   [ENABLED] Adapter: $($adapter.Adapter) - IPv6 is enabled." -ForegroundColor Red
            Write-Host "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.IPv6.status = "FAIL"
            $ipv6Recs += $adapter.Recommendation
            $auditResults.NetworkSecurity.IPv6.comments += "IPv6 is enabled on adapter $($adapter.Adapter). "
        } else {
            Write-Host "   [DISABLED] Adapter: $($adapter.Adapter) - IPv6 is disabled." -ForegroundColor Green
            Write-Host "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
            $ipv6Recs += $adapter.Recommendation
            $auditResults.NetworkSecurity.IPv6.comments += "IPv6 is disabled on adapter $($adapter.Adapter). "
        }
    }
    $auditResults.NetworkSecurity.IPv6.recommendations = ($ipv6Recs | Select-Object -Unique) -join ", "
} else {
    Write-Error "Impossible d'auditer la configuration IPv6 (Get-IPv6Status n'a pas retourne de resultat)"
}

Merge-AuditResults -Section $auditResults.NetworkSecurity.IPv6 -AuditData $ipv6Audit

########## LLMNR Audit ##########

$auditResults.NetworkSecurity.LLMNR = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration LLMNR :" -ForegroundColor Gray
$llmnrAudit = Get-LLMNRState

if (-not $llmnrAudit.Value) {
    Write-Host "   [DEFAULT] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
    $auditResults.NetworkSecurity.LLMNR.status = "FAIL"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is enabled (default). "
} elseif ($llmnrAudit.Value -eq 1) {
    Write-Host "   [ENABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
    $auditResults.NetworkSecurity.LLMNR.status = "FAIL"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is enabled. "
} elseif ($llmnrAudit.Value -eq 0) {
    Write-Host "   [DISABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Green
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Green
    $auditResults.NetworkSecurity.LLMNR.status = "PASS"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is disabled. "
} else {
    Write-Host "   [UNKNOWN] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Yellow
    Write-Host "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
    $auditResults.NetworkSecurity.LLMNR.status = "WARNING"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR status is unknown. "
}
$auditResults.NetworkSecurity.LLMNR.recommendations += $llmnrAudit.Recommendation

Merge-AuditResults -Section $auditResults.NetworkSecurity.LLMNR -AuditData $llmnrAudit

########## NETBIOS Audit ##########

$auditResults.NetworkSecurity.NetBIOS = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration NetBIOS :" -ForegroundColor Gray
$netbiosAudit = Get-NetBiosInfo

if ($netbiosAudit) {
    $hasIssue = $false
    $netbiosRecs = @()
    foreach ($adapter in $netbiosAudit) {
        Write-Host "`n   Interface: $($adapter.Interface)" -ForegroundColor Cyan
        Write-Host "   Statut NetBIOS: $($adapter.NetBIOS_Status)" -ForegroundColor Gray
        Write-Host "   Code TcpipNetbiosOptions: $($adapter.TcpipNetbiosOptions)" -ForegroundColor Gray
        
        # Affichage conditionnel selon le statut
        switch ($adapter.TcpipNetbiosOptions) {
            2 {
                Write-Host "   [OK] $($adapter.Recommendation)" -ForegroundColor Green
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is disabled on adapter $($adapter.Interface). "
            }
            1 {
                Write-Host "   [ALERTE] $($adapter.Recommendation)" -ForegroundColor Red
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is enabled via DHCP on adapter $($adapter.Interface). "
                $hasIssue = $true
            }
            0 {
                Write-Host "   [MOYEN] $($adapter.Recommendation)" -ForegroundColor Red
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is enabled on adapter $($adapter.Interface). "
                $hasIssue = $true
            }
            default {
                Write-Host "   [INFORMATION] $($adapter.Recommendation)" -ForegroundColor Yellow
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS status unknown on adapter $($adapter.Interface). "
                $hasIssue = $true
            }
        }
    }
    $auditResults.NetworkSecurity.NetBIOS.status = if ($hasIssue) { "FAIL" } else { "PASS" }
    $auditResults.NetworkSecurity.NetBIOS.recommendations = ($netbiosRecs | Select-Object -Unique) -join " | "
} else {
    Write-Error "Impossible d'auditer la configuration NetBIOS" #-ErrorAction SilentlyContinue
}

Merge-AuditResults -Section $auditResults.NetworkSecurity.NetBIOS -AuditData $netbiosAudit

########## FIREWALL Audit ##########
$auditResults.NetworkSecurity.Firewall = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit du pare-feu (Windows Firewall) :" -ForegroundColor Gray
$fwAudit = Get-FirewallAudit

if ($fwAudit) {

    # Etat du service Firewall
    if ($fwAudit.FirewallServiceStatus -eq 'NotFound') {
        Write-Host "   [INFORMATION] Le service Windows Firewall (mpssvc) n'a pas ete trouve." -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
        $auditResults.NetworkSecurity.Firewall.status = "FAIL"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service not found. "
    }
    elseif (-not $fwAudit.FirewallServiceRunning) {
        Write-Host "   [ALERTE] Le service Windows Firewall existe mais n'est pas demarre : $($fwAudit.FirewallServiceStatus)" -ForegroundColor Red
        Write-Host "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
        $auditResults.NetworkSecurity.Firewall.status = "FAIL"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service not running: $($fwAudit.FirewallServiceStatus). "
    }
    else {
        Write-Host "   [OK] Le service Windows Firewall est en cours d'execution." -ForegroundColor Green
        Write-Host "   [PROFIL ACTIF] : $($fwAudit.ActiveProfile)" -ForegroundColor Gray
        $auditResults.NetworkSecurity.Firewall.status = "PASS"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service is running on active profile: $($fwAudit.ActiveProfile). "
    }

    # Details et recommandations RDP
    $fwRecs = @()
    if ($fwAudit.RdpRuleDetails) {
        Write-Host "`n   Regles RDP detectees (nom / LocalAddress / RemoteAddress) :" -ForegroundColor Gray
        foreach ($r in $fwAudit.RdpRuleDetails) {
            Write-Host "      - $($r.Name)    Local: $($r.LocalAddress)    Remote: $($r.RemoteAddress)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.Firewall.comments += "RDP rule detected: $($r.Name). "
        }

        if ($fwAudit.RdpRecommendations) {
            Write-Host "`n   Recommandations RDP :" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) { 
                Write-Host "      - $rec" -ForegroundColor Yellow
                $fwRecs += $rec
            }
        }
    }
    else {
        Write-Host "`n   [INFO] Aucune regle RDP activee detectee." -ForegroundColor Gray
        if ($fwAudit.RdpRecommendations -and ($fwAudit.RdpRecommendations | Measure-Object).Count -gt 0) {
            Write-Host "   Recommandation : $($fwAudit.RdpRecommendations -join '; ')" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) {
                $fwRecs += $rec
            }
        }
    }

    # Recommandations globales
    if ($fwAudit.GlobalRecommendations -and ($fwAudit.GlobalRecommendations | Measure-Object).Count -gt 0) {
        Write-Host "`n   Recommandations globales :" -ForegroundColor Yellow
        foreach ($g in $fwAudit.GlobalRecommendations) { 
            Write-Host "      - $g" -ForegroundColor Yellow
            $fwRecs += $g
        }
    }
    $auditResults.NetworkSecurity.Firewall.recommendations = ($fwRecs | Select-Object -Unique) -join " | "
}
else {
    Write-Error "Impossible d'auditer le pare-feu (Get-FirewallAudit n'a pas retourne de resultat)"
}

Merge-AuditResults -Section $auditResults.NetworkSecurity.Firewall -AuditData $fwAudit

########## VPN Audit ##########
$auditResults.NetworkSecurity.VPN = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit des connexions VPN :" -ForegroundColor Gray
$vpnStatus = Get-VPNStatus

if ($vpnStatus) {
    Write-Host "   Description : $($vpnStatus.Description)" -ForegroundColor Gray

    if ($vpnStatus.HasVpnAdapters) {
        Write-Host "`n   Interfaces VPN/TAP/TUN actives detectees :" -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.status = "WARNING"
        foreach ($a in $vpnStatus.Adapters) {
            Write-Host "      - $($a.Name) | $($a.InterfaceDescription) | $($a.Status)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.VPN.comments += "VPN adapter detected: $($a.Name) ($($a.Status)). "
        }
        $auditResults.NetworkSecurity.VPN.recommendations += "Review VPN adapter configurations for security. | "
    } else {
        Write-Host "   [INFO] Aucune interface VPN/TAP/TUN active detectee." -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.status = "PASS"
        $auditResults.NetworkSecurity.VPN.comments += "No active VPN/TAP/TUN adapters detected. "
    }

    if ($vpnStatus.HasVpnProfiles) {
        Write-Host "`n   Profils VPN configures : $($vpnStatus.VpnProfiles.Count)" -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.comments += "$($vpnStatus.VpnProfiles.Count) VPN profile(s) configured. "
        if ($vpnStatus.HasActiveVpnProfiles) {
            Write-Host "   Profils VPN connectes : $($vpnStatus.ActiveVpnProfiles.Count)" -ForegroundColor Green
            $auditResults.NetworkSecurity.VPN.comments += "$($vpnStatus.ActiveVpnProfiles.Count) VPN profile(s) connected. "
            if ([string]::IsNullOrWhiteSpace($auditResults.NetworkSecurity.VPN.status)) {
                $auditResults.NetworkSecurity.VPN.status = "PASS"
            }
        } else {
            Write-Host "   Aucun profil VPN actuellement connecte." -ForegroundColor Yellow
            $auditResults.NetworkSecurity.VPN.comments += "No active VPN profiles connected. "
            if ([string]::IsNullOrWhiteSpace($auditResults.NetworkSecurity.VPN.status)) {
                $auditResults.NetworkSecurity.VPN.status = "PASS"
            }
        }
    } else {
        Write-Host "   [INFO] Aucun profil VPN configure via le client Windows." -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.status = if ([string]::IsNullOrWhiteSpace($auditResults.NetworkSecurity.VPN.status)) { "PASS" } else { $auditResults.NetworkSecurity.VPN.status }
        $auditResults.NetworkSecurity.VPN.comments += "No VPN profiles configured via Windows VPN client. "
    }
} else {
    Write-Error "Impossible d'auditer le VPN (Get-VPNStatus n'a pas retourne de resultat)"
}

Merge-AuditResults -Section $auditResults.NetworkSecurity.VPN -AuditData $vpnStatus

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10

##########################################
#           OS Security Audit            #
##########################################
$auditResults.OSSecurity = @{}

########## Optional Features Audit ##########

$auditResults.OSSecurity.OptionalFeatures = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

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
            $auditResults.OSSecurity.OptionalFeatures.status = "FAIL"
            $featRecs = @()
            foreach ($f in $risky) {
                Write-Host "      - $($f.FeatureName) : $($f.RiskNote)" -ForegroundColor Yellow
                Write-Host "         Recommandation : $($f.Recommendation)" -ForegroundColor Yellow
                Write-Host "         Action suggeree (exemple) : Disable-WindowsOptionalFeature -Online -FeatureName `"$($f.FeatureName)`" -NoRestart" -ForegroundColor DarkGray
                $featRecs += $f.Recommendation
                $auditResults.OSSecurity.OptionalFeatures.comments += "$($f.FeatureName): $($f.RiskNote). "
                $auditResults.OSSecurity.OptionalFeatures.automatable = $true
            }
            $auditResults.OSSecurity.OptionalFeatures.recommendations = ($featRecs | Select-Object -Unique) -join " | "
        } else {
            Write-Host "   [OK] Aucune fonctionnalite optionnelle notablement risquee detectee." -ForegroundColor Green
            $auditResults.OSSecurity.OptionalFeatures.status = "PASS"
            $auditResults.OSSecurity.OptionalFeatures.comments += "No risky optional features detected. "
        }
    } else {
        Write-Host "   [INFO] Aucune fonctionnalite optionnelle activee detectee." -ForegroundColor Yellow
        $auditResults.OSSecurity.OptionalFeatures.status = "PASS"
        $auditResults.OSSecurity.OptionalFeatures.comments += "No optional features enabled. "
    }
}
catch {
    Write-Warning "Erreur lors de l'audit des fonctionnalites optionnelles : $($_.Exception.Message)"
    $auditResults.OSSecurity.OptionalFeatures.status = "WARNING"
    $auditResults.OSSecurity.OptionalFeatures.comments += "Error auditing optional features: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.OptionalFeatures -AuditData $optFeatures


########## AppLocker Audit ##########

$auditResults.OSSecurity.AppLocker = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration AppLocker :" -ForegroundColor Gray
try {
    $appLockerState = Get-AppLockerState

    if ($appLockerState) {
        if ($appLockerState.AppLockerPresent) {
            # AppLocker est present
            if ($appLockerState.AnyRuleEnabled) {
                Write-Host "   [OK] AppLocker est present et au moins une collection de regles est en mode Enforced." -ForegroundColor Green
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Green
                $auditResults.OSSecurity.AppLocker.status = "PASS"
                $auditResults.OSSecurity.AppLocker.comments += "AppLocker is present and at least one rule collection is in Enforced mode. $($appLockerState.Comment). "
            } else {
                Write-Host "   [INFO] AppLocker est present mais aucune collection de regles n'est en mode Enforced." -ForegroundColor Yellow
                Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
                $auditResults.OSSecurity.AppLocker.status = "WARNING"
                $auditResults.OSSecurity.AppLocker.comments += "AppLocker is present but no rule collection is in Enforced mode. $($appLockerState.Comment). "
            }
        } else {
            # Aucune politique AppLocker effective
            Write-Host "   [ALERTE] Aucune politique AppLocker effective detectee sur ce systeme." -ForegroundColor Red
            Write-Host "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
            $auditResults.OSSecurity.AppLocker.status = "FAIL"
            $auditResults.OSSecurity.AppLocker.comments += "No effective AppLocker policy detected. $($appLockerState.Comment). "
        }

        # Affichage de la recommandation
        Write-Host "       Recommandation : $($appLockerState.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.AppLocker.recommendations += $appLockerState.Recommendation
    } else {
        Write-Error "Impossible d'auditer AppLocker (Get-AppLockerState n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Erreur lors de l'audit AppLocker : $($_.Exception.Message)"
    $auditResults.OSSecurity.AppLocker.status = "WARNING"
    $auditResults.OSSecurity.AppLocker.comments += "Error auditing AppLocker: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.AppLocker -AuditData $appLockerState

########## SRP Audit ##########


$auditResults.OSSecurity.SRP = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la configuration SRP (Software Restriction Policies) :" -ForegroundColor Gray
try {
    $srpAudit = Get-SRPState

    if ($srpAudit) {
        $srpDetected = $false
        foreach ($srp in $srpAudit) {
            Write-Host "`n   Scope: $($srp.Scope)" -ForegroundColor Cyan
            
            if ($srp.SRPPresent) {
                Write-Host "   [DeTECTe] SRP est configure pour ce scope." -ForegroundColor Yellow
                $auditResults.OSSecurity.SRP.status = "PASS"
                $srpDetected = $true
                $auditResults.OSSecurity.SRP.comments += "SRP is configured for scope: $($srp.Scope). "
            } else {
                Write-Host "   [ABSENT] Aucune SRP detectee pour ce scope." -ForegroundColor Green
                if (-not $srpDetected) { $auditResults.OSSecurity.SRP.status = "FAIL" }
                $auditResults.OSSecurity.SRP.comments += "No SRP for scope $($srp.Scope). "
            }
            
            Write-Host "   Chemin du registre: $($srp.RegistryPath)" -ForegroundColor Gray
            Write-Host "   Statut: $($srp.Comment)" -ForegroundColor Gray
            Write-Host "   Recommandation: $($srp.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.SRP.recommendations += $srp.Recommendation
        }
        if (-not $srpDetected) { $auditResults.OSSecurity.SRP.status = "FAIL" }
    } else {
        Write-Error "Impossible d'auditer SRP (Get-SRPState n'a pas retourne de resultat)"
        $auditResults.OSSecurity.SRP.status = "WARNING"
        $auditResults.OSSecurity.SRP.comments += "No SRP audit results returned. "
    }
}
catch {
    Write-Warning "Get-SRPState a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.SRP.status = "WARNING"
    $auditResults.OSSecurity.SRP.comments += "Error auditing SRP: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.SRP -AuditData $srpAudit


########## Server Antivirus Status Audit ##########

$auditResults.OSSecurity.ServerAntivirusStatus = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de l'etat des services antivirus :" -ForegroundColor Gray
$antivirusStatus = Get-ServerAntivirusStatus

if ($antivirusStatus) {
    $hasIssue = $false
    $avRecs = @()
    foreach ($av in $antivirusStatus) {
        Write-Host "`nService : $($av.Name)" -ForegroundColor Cyan
        
        if ($av.Present -eq $false) {
            Write-Host "   [ALERTE] Aucune solution antivirus detectee sur ce serveur." -ForegroundColor Red
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.ServerAntivirusStatus.status = "FAIL"
            $auditResults.OSSecurity.ServerAntivirusStatus.comments += "No antivirus solution detected. "
            $auditResults.OSSecurity.ServerAntivirusStatus.recommendations += $av.Recommendation
            $hasIssue = $true
        } else {
            # Statut du service
            if ($av.ServiceRunning) {
                Write-Host "   [OK] Le service antivirus est en cours d'execution." -ForegroundColor Green
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Antivirus service is running. "
            } else {
                Write-Host "   [ALERTE] Le service antivirus n'est pas en cours d'execution." -ForegroundColor Red
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Antivirus service is not running. "
                $hasIssue = $true
            }

            # Monitoring en temps reel (pour Defender uniquement)
            if ($null -ne $av.RealtimeMonitoring) {
                if ($av.RealtimeMonitoring) {
                    Write-Host "   [OK] La protection en temps reel est activee." -ForegroundColor Green
                    $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Real-time monitoring is enabled. "
                } else {
                    Write-Host "   [ALERTE] La protection en temps reel est desactivee." -ForegroundColor Red
                    $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Real-time monitoring is disabled. "
                    $hasIssue = $true
                }
            }

            # Status global
            if ($av.OverallProtected) {
                Write-Host "   [OK] Protection globale : Active" -ForegroundColor Green
            } else {
                Write-Host "   [ALERTE] Protection globale : Inactive ou degradee" -ForegroundColor Red
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Global protection is inactive or degraded. "
                $hasIssue = $true
            }

            # Contexte serveur
            if ($av.IsDomainController) {
                Write-Host "   [INFO] Cette machine est un controleur de domaine." -ForegroundColor Magenta
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "This machine is a Domain Controller. "
            }

            # Description et recommandation
            Write-Host "   Description : $($av.Description)" -ForegroundColor Gray
            Write-Host "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
            $avRecs += $av.Recommendation
        }
    }
    $auditResults.OSSecurity.ServerAntivirusStatus.status = if ($hasIssue) { "FAIL" } else { "PASS" }
    $auditResults.OSSecurity.ServerAntivirusStatus.recommendations = ($avRecs | Select-Object -Unique) -join " | "
} else {
    Write-Error "Impossible d'auditer l'etat des services antivirus (Get-ServerAntivirusStatus n'a pas retourne de resultat)"
    $auditResults.OSSecurity.ServerAntivirusStatus.status = "WARNING"
}

Merge-AuditResults -Section $auditResults.OSSecurity.ServerAntivirusStatus -AuditData $antivirusStatus

########## LM Hash Status Audit ##########

$auditResults.OSSecurity.LMHash = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

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
            $auditResults.OSSecurity.LMHash.status = "FAIL"
            $auditResults.OSSecurity.LMHash.comments += "LM hashes may be stored on this system (NoLMHash != 1). "
        } else {
            Write-Host "   [OK] Les hachs LM ne sont pas stockes (NoLMHash = 1)." -ForegroundColor Green
            Write-Host "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.LMHash.status = "PASS"
            $auditResults.OSSecurity.LMHash.comments += "LM hashes are not stored (NoLMHash = 1). "
        }
        $auditResults.OSSecurity.LMHash.recommendations += $lm.Recommendation

        # Affichage des actions proposees
        if ($lmHashStatus.Xml) {
            Write-Host "`n   Action proposee :" -ForegroundColor Gray
            Write-Host "      - $($lmHashStatus.Xml.Category) : $($lmHashStatus.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($lmHashStatus.Xml.Command)" -ForegroundColor DarkGray
            $auditResults.OSSecurity.LMHash.automatable = $true
            $remediationActions += $lmHashStatus.Xml
        }
    } else {
        Write-Error "Impossible d'auditer la configuration LM Hash (Get-LMHashStatus n'a pas retourne de resultat)"
    }
}
catch {
    Write-Warning "Get-LMHashStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.LMHash.status = "WARNING"
    $auditResults.OSSecurity.LMHash.comments += "Error auditing LM Hash: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.LMHash -AuditData $lmHashStatus

########## LSASS Protection Audit ##########

$auditResults.OSSecurity.LSASSProtection = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit de la protection LSASS :" -ForegroundColor Gray
try {
    $lsassAudit = Get-LsassProtectionStatus

    if ($lsassAudit -and $lsassAudit.Value) {
        $p = $lsassAudit.Value

        Write-Host "   LSA Path : $($p.LsaPath)" -ForegroundColor Gray
        Write-Host "   RunAsPPL : $($p.RunAsPPL)" -ForegroundColor Gray

        $lsassOk = $false
        switch ($p.RunAsPPL) {
            2 {
                Write-Host "   [OK] LSA protection activee (RunAsPPL = 2, Secure Boot requis)." -ForegroundColor Green
                $lsassOk = $true
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is enabled (RunAsPPL = 2, Secure Boot required). "
            }
            1 {
                Write-Host "   [OK] LSA protection activee (RunAsPPL = 1)." -ForegroundColor Green
                $lsassOk = $true
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is enabled (RunAsPPL = 1). "
            }
            default {
                Write-Host "   [ALERTE] LSA protection non activee ou valeur inconnue." -ForegroundColor Red
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is not enabled or unknown value. "
            }
        }

        Write-Host "   WDigest Path : $($p.WDigestPath)" -ForegroundColor Gray
        Write-Host "   UseLogonCredential : $($p.UseLogonCredential)" -ForegroundColor Gray

        if ($p.UseLogonCredential -eq 1) {
            Write-Host "   [ALERTE] WDigest active — mots de passe potentiellement stockes en clair dans LSASS." -ForegroundColor Red
            $auditResults.OSSecurity.LSASSProtection.comments += "WDigest is enabled - passwords may be stored in LSASS. "
            $lsassOk = $false
        } else {
            Write-Host "   [OK] WDigest desactive ou valeur explicite presente." -ForegroundColor Green
            $auditResults.OSSecurity.LSASSProtection.comments += "WDigest is disabled. "
        }

        Write-Host "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.LSASSProtection.recommendations += $p.Recommendation

        if ($lsassAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $lsassAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
                $auditResults.OSSecurity.LSASSProtection.automatable = $true
                $remediationActions += $item
            }
        }
        
        $auditResults.OSSecurity.LSASSProtection.status = if ($lsassOk) { "PASS" } else { "FAIL" }
    } else {
        Write-Error "Impossible d'auditer LSASS (Get-LsassProtectionStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.LSASSProtection.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-LsassProtectionStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.LSASSProtection.status = "WARNING"
    $auditResults.OSSecurity.LSASSProtection.comments += "Error auditing LSASS: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.LSASSProtection -AuditData $lsassAudit

########## Credential Guard Audit ##########

$auditResults.OSSecurity.CredentialGuard = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit Credential Guard :" -ForegroundColor Gray
try {
    $cg = Get-CredentialGuardStatus

    if ($cg) {
        Write-Host "   LsaPath        : $($cg.LsaPath)" -ForegroundColor Gray
        Write-Host "   LsaCfgFlags    : $($cg.LsaCfgFlags)" -ForegroundColor Gray
        Write-Host "   Status         : $($cg.CredentialGuard)" -ForegroundColor Gray

        $cgEnabled = $false
        if ($cg.LsaCfgFlags -eq 1 -or $cg.LsaCfgFlags -eq 2) {
            Write-Host "   [OK] Credential Guard active." -ForegroundColor Green
            $cgEnabled = $true
            $auditResults.OSSecurity.CredentialGuard.comments += "Credential Guard is enabled (LsaCfgFlags = $($cg.LsaCfgFlags)). "
        } else {
            Write-Host "   [ALERTE] Credential Guard desactive ou non configure." -ForegroundColor Red
            $auditResults.OSSecurity.CredentialGuard.comments += "Credential Guard is disabled or not configured (LsaCfgFlags = $($cg.LsaCfgFlags)). "
        }

        Write-Host "   TPM present    : $($cg.HasTPM)" -ForegroundColor Gray
        Write-Host "   SecureBoot     : $($cg.SecureBoot)" -ForegroundColor Gray
        Write-Host "   Virtualisation : $($cg.Virtualization)" -ForegroundColor Gray

        if (-not $cg.HasTPM -or -not $cg.SecureBoot -or -not $cg.Virtualization) {
            Write-Host "`n   [PREREQUIS MANQUANTS]" -ForegroundColor Yellow
            if (-not $cg.HasTPM)    { Write-Host "      - TPM manquant ou version non supportee." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "TPM not available. " }
            if (-not $cg.SecureBoot){ Write-Host "      - Secure Boot non active." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "Secure Boot not enabled. " }
            if (-not $cg.Virtualization) { Write-Host "      - Virtualisation materielle non presente." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "Virtualization not available. " }
            $auditResults.OSSecurity.CredentialGuard.status = "WARNING"
        } else {
            $auditResults.OSSecurity.CredentialGuard.status = if ($cgEnabled) { "PASS" } else { "FAIL" }
        }
        
        Write-Host "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Yellow
        $auditResults.OSSecurity.CredentialGuard.recommendations += "$cg.Recommendations"
    }
    else {
        Write-Error "Impossible d'auditer Credential Guard (Get-CredentialGuardStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.CredentialGuard.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-CredentialGuardStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.CredentialGuard.status = "WARNING"
    $auditResults.OSSecurity.CredentialGuard.comments += "Error auditing Credential Guard: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.CredentialGuard -AuditData $cg

########## Device Guard / VBS Audit ##########

$auditResults.OSSecurity.DeviceGuard_VBS = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

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

            $auditResults.OSSecurity.DeviceGuard_VBS.status = "PASS"
            $auditResults.OSSecurity.DeviceGuard_VBS.comments += "VBS and/or WDAC is active. "

            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Audit') {
                Write-Host "   [INFO] WDAC en mode Audit — examiner les journaux et prevoir passage en Enforced si stable." -ForegroundColor Yellow
                $auditResults.OSSecurity.DeviceGuard_VBS.comments += "WDAC is in Audit mode. "
                $auditResults.OSSecurity.DeviceGuard_VBS.status = "WARNING"
            }
            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Enforced') {
                Write-Host "   [OK] WDAC / Code Integrity en mode Enforced." -ForegroundColor Green
                $auditResults.OSSecurity.DeviceGuard_VBS.comments += "WDAC is in Enforced mode. "
            }
        }
        else {
            Write-Host "   [ALERTE] Ni VBS ni WDAC actives sur ce systeme." -ForegroundColor Red
            $auditResults.OSSecurity.DeviceGuard_VBS.status = "FAIL"
            $auditResults.OSSecurity.DeviceGuard_VBS.comments += "Neither VBS nor WDAC is active. "
        }
        
        Write-Host "   Recommandation : $($dg.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.DeviceGuard_VBS.recommendations += $dg.Recommendation
    }
    else {
        Write-Error "Impossible d'auditer Device Guard (Get-DeviceGuardStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.DeviceGuard_VBS.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-DeviceGuardStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.DeviceGuard_VBS.status = "WARNING"
    $auditResults.OSSecurity.DeviceGuard_VBS.comments += "Error auditing Device Guard: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.DeviceGuard_VBS -AuditData $dg


########## Exploit Protection / Process Mitigations Audit ##########

$auditResults.OSSecurity.ExploitProtection = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

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
            $auditResults.OSSecurity.ExploitProtection.status = "PASS"
            $auditResults.OSSecurity.ExploitProtection.comments += "Exploit Protection settings are strong. "
        } else {
            Write-Host "      [ALERTE] Parametres manquants ou desactives : $($issues -join ', ')" -ForegroundColor Red
            Write-Host "      Recommandation : $($ep.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.ExploitProtection.status = "FAIL"
            $auditResults.OSSecurity.ExploitProtection.comments += "Missing or disabled settings: $($issues -join ', '). "
        }
        
        $auditResults.OSSecurity.ExploitProtection.recommendations += $ep.Recommendation

        if ($epAudit.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $epAudit.Xml) {
                Write-Host "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Write-Host "         Commande : $($item.Command)" -ForegroundColor DarkGray
                $auditResults.OSSecurity.ExploitProtection.automatable = $true
                $remediationActions += $item
            }
        }
    }
    else {
        Write-Error "Impossible d'auditer Exploit Protection (Get-ExploitProtectionStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.ExploitProtection.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-ExploitProtectionStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.ExploitProtection.status = "WARNING"
    $auditResults.OSSecurity.ExploitProtection.comments += "Error auditing Exploit Protection: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.ExploitProtection -AuditData $epAudit

########## ASR (Attack Surface Reduction) Audit ##########

$auditResults.OSSecurity.ASR = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit Attack Surface Reduction (ASR) :" -ForegroundColor Gray
try {
    $asrAudit = Get-ASRStatus

    if (-not $asrAudit) {
        Write-Error "Impossible d'auditer ASR (Get-ASRStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.ASR.status = "WARNING"
    }
    elseif ($asrAudit -is [System.Collections.IEnumerable] -and ($asrAudit | Where-Object { $_.RuleId })) {
        $hasBlockedRules = $false
        foreach ($rule in $asrAudit) {
            $status = $rule.Action
            switch ($status) {
                'Block'  { $color = 'Green' ; $label = '[ENFORCED]'; $hasBlockedRules = $true }
                'Audit'  { $color = 'Yellow'; $label = '[AUDIT]' }
                'Warn'   { $color = 'Magenta'; $label = '[WARN]' }
                'Disabled' { $color = 'Red'; $label = '[DISABLED]' }
                default  { $color = 'Gray'; $label = "[UNKNOWN]" }
            }

            Write-Host "`n   RuleId : $($rule.RuleId)  $label" -ForegroundColor Cyan
            Write-Host "      Mode : $status" -ForegroundColor $color
            Write-Host "      Commentaire : $($rule.Comment)" -ForegroundColor Gray
            if ($rule.Recommendation) { 
                Write-Host "      Recommandation : $($rule.Recommendation)" -ForegroundColor Yellow
                $auditResults.OSSecurity.ASR.recommendations += $rule.Recommendation
            }
            $auditResults.OSSecurity.ASR.comments += "Rule $($rule.RuleId) is $status. "
        }
        $auditResults.OSSecurity.ASR.status = if ($hasBlockedRules) { "PASS" } else { "WARNING" }
    }
    else {
        # Cas ou Get-ASRStatus renvoie un objet unique indiquant l'absence de regles
        Write-Host "   $($asrAudit.Comment)" -ForegroundColor Red
        Write-Host "   Recommandation : $($asrAudit.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.ASR.status = "FAIL"
        $auditResults.OSSecurity.ASR.comments += "$($asrAudit.Comment). "
        $auditResults.OSSecurity.ASR.recommendations += $asrAudit.Recommendation
    }
}
catch {
    Write-Warning "Get-ASRStatus a echoue : $($_.Exception.Message)"
}

Merge-AuditResults -Section $auditResults.OSSecurity.ASR -AuditData $asrAudit

########## Network Protection (Defender) Audit ##########

$auditResults.OSSecurity.NetworkProtection = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit Network Protection (Microsoft Defender) :" -ForegroundColor Gray
try {
    $np = Get-NetworkProtectionStatus

    if ($np) {
        Write-Host "   Mode detecte : $($np.Mode)" -ForegroundColor Gray
        switch ($np.Mode) {
            'Block' {
                Write-Host "   [OK] Network Protection en mode Block." -ForegroundColor Green
                $auditResults.OSSecurity.NetworkProtection.status = "PASS"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is in Block mode. "
            }
            'Audit' {
                Write-Host "   [INFO] Network Protection en mode Audit." -ForegroundColor Yellow
                $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is in Audit mode. "
            }
            'Off' {
                Write-Host "   [ALERTE] Network Protection desactive." -ForegroundColor Red
                $auditResults.OSSecurity.NetworkProtection.status = "FAIL"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is disabled. "
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Network Protection non configure." -ForegroundColor Red
                $auditResults.OSSecurity.NetworkProtection.status = "FAIL"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is not configured. "
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($np.RawValue)" -ForegroundColor Yellow
                $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection has unknown status: $($np.RawValue). "
            }
        }

        Write-Host "   EnableNetworkProtection : $($np.EnableNetworkProtection)" -ForegroundColor Gray
        Write-Host "`n   Recommandation : $($np.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.NetworkProtection.recommendations += $np.Recommendation
    }
    else {
        Write-Error "Impossible d'auditer Network Protection (Get-NetworkProtectionStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-NetworkProtectionStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
    $auditResults.OSSecurity.NetworkProtection.comments += "Error auditing Network Protection: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.NetworkProtection -AuditData $np

########## Controlled Folder Access (CFA) Audit ##########

$auditResults.OSSecurity.ControlledFolderAccess = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit Controlled Folder Access (Defender) :" -ForegroundColor Gray
try {
    $cfa = Get-ControlledFolderAccessStatus

    if ($cfa) {
        Write-Host "   Mode detecte : $($cfa.Mode)" -ForegroundColor Gray

        switch ($cfa.Mode) {
            'Block' {
                Write-Host "   [OK] Controlled Folder Access en mode Block." -ForegroundColor Green
                $auditResults.OSSecurity.ControlledFolderAccess.status = "PASS"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Block mode. "
            }
            'Audit' {
                Write-Host "   [INFO] Controlled Folder Access en mode Audit." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Audit mode. "
            }
            'Block disk modification only' {
                Write-Host "   [INFO] CFA en mode 'Block disk modification only'." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Block disk modification only mode. "
            }
            'Audit disk modification only' {
                Write-Host "   [INFO] CFA en mode 'Audit disk modification only'." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Audit disk modification only mode. "
            }
            'Off' {
                Write-Host "   [ALERTE] Controlled Folder Access desactive." -ForegroundColor Red
                $auditResults.OSSecurity.ControlledFolderAccess.status = "FAIL"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is disabled. "
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Controlled Folder Access non configure." -ForegroundColor Red
                $auditResults.OSSecurity.ControlledFolderAccess.status = "FAIL"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is not configured. "
            }
            default {
                Write-Host "   [INCONNU] Valeur brute : $($cfa.EnableControlledFolderAccess)" -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access has unknown status: $($cfa.EnableControlledFolderAccess). "
            }
        }

        Write-Host "`n   Recommandation : $($cfa.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.ControlledFolderAccess.recommendations += $cfa.Recommendation
    }
    else {
        Write-Error "Impossible d'auditer Controlled Folder Access (Get-ControlledFolderAccessStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-ControlledFolderAccessStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
    $auditResults.OSSecurity.ControlledFolderAccess.comments += "Error auditing Controlled Folder Access: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.ControlledFolderAccess -AuditData $cfa

########## Smart App Control Audit ##########

$auditResults.OSSecurity.SmartAppControl = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit Smart App Control :" -ForegroundColor Gray
try {
    $sac = Get-SmartAppControlStatus

    if ($sac) {
        Write-Host "   Smart App Control : $($sac.SmartApp_State)" -ForegroundColor Gray

        switch ($sac.SmartApp_State) {
            'On' {
                Write-Host "   [OK] Smart App Control active." -ForegroundColor Green
                $auditResults.OSSecurity.SmartAppControl.status = "PASS"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is enabled. "
            }
            'Evaluation' {
                Write-Host "   [INFO] Smart App Control en mode Evaluation." -ForegroundColor Yellow
                $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is in Evaluation mode. "
            }
            'Off' {
                Write-Host "   [ALERTE] Smart App Control desactive." -ForegroundColor Red
                $auditResults.OSSecurity.SmartAppControl.status = "FAIL"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is disabled. "
            }
            'NotConfigured' {
                Write-Host "   [ALERTE] Smart App Control non configure." -ForegroundColor Red
                $auditResults.OSSecurity.SmartAppControl.status = "FAIL"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is not configured. "
            }
            default {
                Write-Host "   [INCONNU] Valeur detectee : $($sac.SmartApp_State)" -ForegroundColor Yellow
                $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control has unknown state: $($sac.SmartApp_State). "
            }
        }
        Write-Host "`n   Recommandation : Tester en mode Evaluation puis activer (On) sur systemes compatibles." -ForegroundColor Yellow
        $auditResults.OSSecurity.SmartAppControl.recommendations += "Test in Evaluation mode then enable (On) on compatible systems."
    }
    else {
        Write-Error "Impossible d'auditer Smart App Control (Get-SmartAppControlStatus n'a pas retourne de resultat)"
        $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-SmartAppControlStatus a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
    $auditResults.OSSecurity.SmartAppControl.comments += "Error auditing Smart App Control: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.SmartAppControl -AuditData $sac

########## PowerShell Language Mode Audit ##########

$auditResults.OSSecurity.PowershellLanguageMode = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit du mode langage PowerShell :" -ForegroundColor Gray
try {
    $psMode = Get-PowerShellLanguageMode

    if ($psMode) {
        Write-Host "   LanguageMode : $($psMode.LanguageMode)" -ForegroundColor Gray

        if ($psMode.IsConstrained) {
            Write-Host "   [OK] PowerShell en ConstrainedLanguage." -ForegroundColor Green
            $auditResults.OSSecurity.PowershellLanguageMode.status = "PASS"
            $auditResults.OSSecurity.PowershellLanguageMode.comments += "PowerShell is in ConstrainedLanguage mode. "
        }
        else {
            Write-Host "   [ALERTE] PowerShell en FullLanguage (ou moins restreint)." -ForegroundColor Red
            $auditResults.OSSecurity.PowershellLanguageMode.status = "FAIL"
            $auditResults.OSSecurity.PowershellLanguageMode.comments += "PowerShell is in FullLanguage or less restricted mode: $($psMode.LanguageMode). "
        }
        Write-Host "   Recommandation : $($psMode.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.PowershellLanguageMode.recommendations += $psMode.Recommendation
    }
    else {
        Write-Error "Impossible d'auditer le mode PowerShell (Get-PowerShellLanguageMode n'a pas retourne de resultat)"
        $auditResults.OSSecurity.PowershellLanguageMode.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-PowerShellLanguageMode a echoue : $($_.Exception.Message)"
    $auditResults.OSSecurity.PowershellLanguageMode.status = "WARNING"
    $auditResults.OSSecurity.PowershellLanguageMode.comments += "Error auditing PowerShell Language Mode: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.OSSecurity.PowershellLanguageMode -AuditData $psMode

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10

##########################################
#             Device Security            #
##########################################
$auditResults.DeviceSecurity = @{}

########## AutoRun / NoDriveTypeAutorun Audit ##########

$auditResults.DeviceSecurity.AutoRun = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit AutoRun (NoDriveTypeAutorun) :" -ForegroundColor Gray
try {
    $ar = Get-AutorunStatus

    if ($ar -and $ar.Value) {
        $hasIssue = $false
        $arRecs = @()
        foreach ($entry in $ar.Value) {
            Write-Host "`n   Scope : $($entry.Scope)" -ForegroundColor Cyan
            Write-Host "      Valeur brute : $($entry.Value)" -ForegroundColor Gray
            Write-Host "      Commentaire  : $($entry.Comment)" -ForegroundColor Gray

            if ($entry.AutoRunEnabled -eq $true) {
                Write-Host "      [ALERTE] Autorun potentiellement active." -ForegroundColor Red
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Yellow
                $auditResults.DeviceSecurity.AutoRun.comments += "AutoRun is potentially enabled for scope $($entry.Scope). "
                $arRecs += $entry.Recommendation
                $hasIssue = $true
            }
            else {
                Write-Host "      [OK] Autorun desactive pour ce scope." -ForegroundColor Green
                Write-Host "      Recommandation : $($entry.Recommendation)" -ForegroundColor Gray
                $auditResults.DeviceSecurity.AutoRun.comments += "AutoRun is disabled for scope $($entry.Scope). "
                $arRecs += $entry.Recommendation
            }
        }

        if ($ar.Xml) {
            Write-Host "`n   Actions proposees :" -ForegroundColor Gray
            Write-Host "      - $($ar.Xml.Category) : $($ar.Xml.Description)" -ForegroundColor Yellow
            Write-Host "         Commande : $($ar.Xml.Command)" -ForegroundColor DarkGray
            $auditResults.DeviceSecurity.AutoRun.automatable = $true
            $remediationActions += $ar.Xml
        }
        
        $auditResults.DeviceSecurity.AutoRun.status = if ($hasIssue) { "FAIL" } else { "PASS" }
        $auditResults.DeviceSecurity.AutoRun.recommendations = ($arRecs | Select-Object -Unique) -join " | "
    }
    else {
        Write-Error "Impossible d'auditer AutoRun (Get-AutorunStatus n'a pas retourne de resultat)"
        $auditResults.DeviceSecurity.AutoRun.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-AutorunStatus a echoue : $($_.Exception.Message)"
    $auditResults.DeviceSecurity.AutoRun.status = "WARNING"
    $auditResults.DeviceSecurity.AutoRun.comments += "Error auditing AutoRun: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.DeviceSecurity.AutoRun -AuditData $ar

########## BitLocker Audit ##########

$auditResults.DeviceSecurity.BitLocker = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit BitLocker :" -ForegroundColor Gray
try {

    if ($context.HardwareType -ne 'VirtualMachine') {
        
        $bitlocker = Get-BitLockerAudit

        if ($bitlocker) {
            $allEncrypted = $true
            $blRecs = @()
            foreach ($vol in $bitlocker) {
                Write-Host "`n   Volume : $($vol.MountPoint) ($($vol.VolumeType))" -ForegroundColor Cyan
                Write-Host "      ProtectionStatus   : $($vol.ProtectionStatus)  |  Chiffrement : $($vol.EncryptionPercent)% " -ForegroundColor Gray
                if ($vol.ProtectionStatus -eq 'On' -and $vol.EncryptionPercent -ge 100) {
                    Write-Host "      [OK] Volume chiffre et protege." -ForegroundColor Green
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) is encrypted and protected. "
                }
                elseif ($vol.ProtectionStatus -eq 'Suspended') {
                    Write-Host "      [INFO] Protection suspendue." -ForegroundColor Yellow
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) has suspended protection. "
                    $allEncrypted = $false
                }
                else {
                    Write-Host "      [ALERTE] Volume non protege ou chiffrement incomplet." -ForegroundColor Red
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) is not protected or encryption is incomplete. "
                    $allEncrypted = $false
                }

                Write-Host "      TPM : $($vol.HasTPM)    PIN : $($vol.HasPIN)    RecoveryKey : $($vol.HasRecoveryPassword)" -ForegroundColor Gray
                Write-Host "      Commentaire : $($vol.Comment)" -ForegroundColor Gray
                Write-Host "      Recommandation : $($vol.Recommendation)" -ForegroundColor Yellow
                $blRecs += $vol.Recommendation
            }
            $auditResults.DeviceSecurity.BitLocker.status = if ($allEncrypted) { "PASS" } else { "FAIL" }
            $auditResults.DeviceSecurity.BitLocker.recommendations = ($blRecs | Select-Object -Unique) -join " | "
        }
        else {
            Write-Error "Impossible d'auditer BitLocker (Get-BitLockerAudit n'a pas retourne de resultat)"
            $auditResults.DeviceSecurity.BitLocker.status = "WARNING"
        }
    } else {
        Write-Host "   [INFO] Systeme virtuel detecte — saut de l'audit BitLocker." -ForegroundColor Yellow
        $auditResults.DeviceSecurity.BitLocker.status = "N/A"
        $auditResults.DeviceSecurity.BitLocker.comments += "Virtual machine detected — BitLocker audit skipped. "
    }
}
catch {
    Write-Warning "Get-BitLockerAudit a echoue : $($_.Exception.Message)"
    $auditResults.DeviceSecurity.BitLocker.status = "WARNING"
    $auditResults.DeviceSecurity.BitLocker.comments += "Error auditing BitLocker: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.DeviceSecurity.BitLocker -AuditData $bitlocker


########## Thirda€‘Party Full Disk Encryption Indicators ##########

$auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

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
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Third-party encryption detected: $name. "
                if ($item.Version) { 
                    Write-Host "      Version : $($item.Version)" -ForegroundColor Gray
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Version: $($item.Version). "
                }
                if ($item.Details) { 
                    Write-Host "      Details : $($item.Details)" -ForegroundColor Gray
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Details: $($item.Details). "
                }
                if ($item.Recommendation) { 
                    Write-Host "      Recommandation : $($item.Recommendation)" -ForegroundColor Yellow
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.recommendations += $item.Recommendation
                }
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
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
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Third-party encryption detected. Details: $($tpe.Details). "
            if ($tpe.Recommendation) { 
                Write-Host "   Recommandation : $($tpe.Recommendation)" -ForegroundColor Yellow
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.recommendations += $tpe.Recommendation
            }
        } else {
            Write-Host "   [OK] Aucun chiffrement tiers detecte." -ForegroundColor Magenta
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "No third-party encryption detected. "
        }
    }
    if ([string]::IsNullOrWhiteSpace($auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status)) {
        $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
    }
}
catch {
    Write-Warning "Get-ThirdPartyEncryptionIndicators a echoue : $($_.Exception.Message)"
    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "WARNING"
}

Merge-AuditResults -Section $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators -AuditData $tpe

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10

##########################################
#            Update Management           #
##########################################
$auditResults.UpdateManagement = @{}

########## Last Reboot / Uptime Audit ##########

$auditResults.UpdateManagement.LastReboot_Uptime = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Write-Host "`n[+] Audit du dernier redemarrage :" -ForegroundColor Gray
try {
    $lr = Get-LastReboot

    if ($lr) {
        Write-Host "   Role de la machine : $($lr.ComputerRole)" -ForegroundColor Gray
        Write-Host "   Dernier demarrage   : $($lr.LastBootTime)" -ForegroundColor Gray
        Write-Host "   Uptime              : $($lr.Uptime) (jours: $($lr.UptimeDays))" -ForegroundColor Gray
        Write-Host "   Seuil recommande    : $($lr.ThresholdDays) jours" -ForegroundColor Gray

        $auditResults.UpdateManagement.LastReboot_Uptime.comments += "Last boot time: $($lr.LastBootTime). Uptime: $($lr.UptimeDays) days. "

        if ($lr.UptimeDays -gt $lr.ThresholdDays) {
            Write-Host "   [ALERTE] Uptime superieur au seuil ($($lr.ThresholdDays) jours)." -ForegroundColor Red
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Yellow
            $auditResults.UpdateManagement.LastReboot_Uptime.status = "FAIL"
        }
        else {
            Write-Host "   [OK] Uptime dans la plage attendue." -ForegroundColor Green
            Write-Host "   Recommandation : $($lr.Recommendation)" -ForegroundColor Gray
            $auditResults.UpdateManagement.LastReboot_Uptime.status = "PASS"
        }
        $auditResults.UpdateManagement.LastReboot_Uptime.recommendations += $lr.Recommendation
    }
    else {
        Write-Error "Impossible d'auditer le dernier redemarrage (Get-LastReboot n'a pas retourne de resultat)"
        $auditResults.UpdateManagement.LastReboot_Uptime.status = "WARNING"
    }
}
catch {
    Write-Warning "Get-LastReboot a echoue : $($_.Exception.Message)"
    $auditResults.UpdateManagement.LastReboot_Uptime.status = "WARNING"
    $auditResults.UpdateManagement.LastReboot_Uptime.comments += "Error auditing last reboot: $($_.Exception.Message). "
}

Merge-AuditResults -Section $auditResults.UpdateManagement.LastReboot_Uptime -AuditData $lr

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10

##########################################
#                Logging                 #
##########################################

$auditResults.Logging = @{}
########## Logging / Event Collection Audit ##########

Write-Host "`n[+] Audit des journaux et de la collecte d'evenements :" -ForegroundColor Gray
try {
    $auditResults.Logging.LogStatus = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    # 1) Logs locaux (taille / retention)
    $logs = Get-LogStatus
    if ($logs) {
        $logIssue = $false
        $logRecs = @()
        foreach ($l in $logs) {
            Write-Host "`n   Log : $($l.LogName)" -ForegroundColor Cyan
            if (-not $l.IsEnabled) {
                Write-Host "      [ALERTE] Desactive ou indisponible." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) is disabled. "
                $logRecs += $l.Recommendation
                $logIssue = $true
                continue
            }

            Write-Host "      Enregistres : $($l.RecordCount)  |  MaxSize : $($l.MaximumSizeMB) MB  |  Reco : $($l.RecoSizeMB) MB" -ForegroundColor Gray

            if ($l.IsSizeOK -eq $true) {
                Write-Host "      [OK] Taille du journal conforme." -ForegroundColor Green
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) size is compliant. "
                $logRecs += $l.Recommendation
            }
            elseif ($l.IsSizeOK -eq $false) {
                Write-Host "      [ALERTE] Taille du journal insuffisante." -ForegroundColor Red
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) size is insufficient. "
                $logRecs += $l.Recommendation
                $logIssue = $true
            }
            else {
                Write-Host "      [INFO] Aucune recommandation de taille definie." -ForegroundColor Yellow
                Write-Host "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) has no size recommendation. "
                $logRecs += $l.Recommendation
            }
        }
        $auditResults.Logging.LogStatus.status = if ($logIssue) { "FAIL" } else { "PASS" }
        $auditResults.Logging.LogStatus.recommendations = ($logRecs | Select-Object -Unique) -join " | "
    } else {
        Write-Error "Get-LogStatus n'a pas retourne de resultat."
        $auditResults.Logging.LogStatus.status = "WARNING"
    }

    $auditResults.Logging.EventForwardingStatus = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    # 2) Event Forwarding & Sysmon
    $ef = Get-EventForwardingStatus
    if ($ef) {
        $efIssue = $false
        $efRecs = @()
        foreach ($e in $ef) {
            Write-Host "`n   Source : $($e.Name)" -ForegroundColor Cyan
            Write-Host "      Active : $($e.IsEnabled)" -ForegroundColor Gray
            Write-Host "      Commentaire : $($e.Comment)" -ForegroundColor Gray
            Write-Host "      Recommendation : $($e.Recommendation)" -ForegroundColor Yellow
            
            if ($e.IsEnabled) {
                $auditResults.Logging.EventForwardingStatus.comments += "Event forwarding is enabled for $($e.Name). "
            } else {
                $auditResults.Logging.EventForwardingStatus.comments += "Event forwarding is disabled for $($e.Name). "
                $efIssue = $true
            }
            $efRecs += $e.Recommendation
        }
        $auditResults.Logging.EventForwardingStatus.status = if ($efIssue) { "FAIL" } else { "PASS" }
        $auditResults.Logging.EventForwardingStatus.recommendations = ($efRecs | Select-Object -Unique) -join " | "
    } else {
        Write-Warning "Get-EventForwardingStatus n'a pas retourne de resultat."
        $auditResults.Logging.EventForwardingStatus.status = "WARNING"
    }

    $auditResults.Logging.LogAgentStatus = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    # 3) Recherche d'agents de logs / SIEM
    $agents = Get-LogAgentStatus
    if ($agents) {
        Write-Host "`n   Agents de collecte detectes :" -ForegroundColor Gray
        $agentFound = $false
        $laRecs = @()
        foreach ($a in $agents) {
            if ($a.IsLogAgent) {
                Write-Host "      - $($a.DisplayName) (version: $($a.DisplayVersion))" -ForegroundColor Green
                Write-Host "         Recommendation : $($a.Recommendation)" -ForegroundColor Gray
                $auditResults.Logging.LogAgentStatus.comments += "Log agent detected: $($a.DisplayName) (version: $($a.DisplayVersion)). "
                $laRecs += $a.Recommendation
                $agentFound = $true
            } else {
                Write-Host "      - Aucun agent connu detecte sur l'entree (bruit possible)." -ForegroundColor Yellow
                Write-Host "         Commentaire : $($a.Comment)" -ForegroundColor Gray
                $auditResults.Logging.LogAgentStatus.comments += "Unknown entry detected: $($a.Comment). "
            }
        }
        $auditResults.Logging.LogAgentStatus.status = if ($agentFound) { "PASS" } else { "FAIL" }
        if ($laRecs.Count -gt 0) {
            $auditResults.Logging.LogAgentStatus.recommendations = ($laRecs | Select-Object -Unique) -join " | "
        }
    } else {
        Write-Host "`n   [ALERTE] Aucun agent de collecte/SIEM detecte." -ForegroundColor Red
        Write-Host "      Recommendation : Installer/configurer un agent pour centraliser les logs." -ForegroundColor Yellow
        $auditResults.Logging.LogAgentStatus.status = "FAIL"
        $auditResults.Logging.LogAgentStatus.comments += "No log collection/SIEM agent detected. "
        $auditResults.Logging.LogAgentStatus.recommendations += "Install and configure a log collection agent to centralize logs. | "
    }
}
catch {
    Write-Warning "Audit Logging a echoue : $($_.Exception.Message)"
    $auditResults.Logging.LogStatus.status = "WARNING"
    $auditResults.Logging.EventForwardingStatus.status = "WARNING"
    $auditResults.Logging.LogAgentStatus.status = "WARNING"
}

Merge-AuditResults -Section $auditResults.Logging.LogStatus -AuditData $logs

Export-AuditResultsToJson -AuditData $auditResults -OutputPath $ScriptPath -scriptStartDate $scriptStartDate -Depth 10 | Out-Null

# --- Export remediation actions to XML ---
if ($remediationActions -and $remediationActions.Count -gt 0) {
    try {
        $xmlPath = Join-Path -Path $ScriptPath -ChildPath "xml\remediations_$scriptStartDate.xml"
        $remediationActions | Export-Clixml -Path $xmlPath -Force
        Write-Host "[✓] Actions de remediation exportees : $xmlPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Erreur lors de l'export des actions XML : $($_.Exception.Message)"
    }
}

# --- Fin ---
Write-Host "`nAudit termine." -ForegroundColor Cyan
