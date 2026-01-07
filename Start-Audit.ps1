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

function Add-ToLog {
    param (
        [string]$Message,
        [string]$ForegroundColor = "White"
    )

    Write-Host $Message -ForegroundColor $ForegroundColor
    #ajouter dans le fichier de log
    Add-Content -Path "$PSScriptRoot\audit.log" -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message"
}

# --- Execution de l'Audit ---
Add-ToLog -Message "Demarrage de l'audit sur $env:COMPUTERNAME..." -ForegroundColor Green

# 1. Recuperation du contexte (appel de notre fonction importee)
$context = Get-HostContext

$auditResults.HostContext = $context

if ($context) {
    Add-ToLog -Message "`n[+] Contexte Identifie :" -ForegroundColor Yellow
    $context | Format-List
    
    # Logique conditionnelle base sur le contexte
    if ($context.OSRole -eq "Server") {
        Add-ToLog -Message ">> Mode Audit Serveur active." -ForegroundColor Gray
    }
    elseif ($context.HardwareType -eq "Virtual Machine") {
        Add-ToLog -Message ">> Machine Virtuelle detectee : Verification des Integration Tools requise." -ForegroundColor Gray
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
    Add-ToLog -Message "`n[+] Comptes locaux identifies :" -ForegroundColor Gray
    $auditResults.AccountSecurity.LocalAdminAccount = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }
    if (($localUserAudit.Value.AdminAccountSID -match "-500$") -and ($localUserAudit.Value.AdminEnabled -eq $true)){
        Add-ToLog -Message "`nLe compte Administrateur par defaut est active" -ForegroundColor Red
        Add-ToLog -Message $localUserAudit.Value.AdminRecommandation.Enabled -ForegroundColor Yellow
        $auditResults.AccountSecurity.LocalAdminAccount.status = "FAIL"
        $auditResults.AccountSecurity.LocalAdminAccount.recommendations += $localUserAudit.Value.AdminRecommandation.Enabled
        $auditResults.AccountSecurity.LocalAdminAccount.comments += "Administrator default account is enabled."     
    }
    else {
        Add-ToLog -Message "$($localUserAudit.Value.AdminRecommandation.Disabled)" -ForegroundColor Green
        
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
        Add-ToLog -Message "`nLe compte Invite par defaut est active" -ForegroundColor Red
        Add-ToLog -Message $localUserAudit.Value.GuestRecommandation.Enabled -ForegroundColor Yellow
        $auditResults.AccountSecurity.LocalGuestAccount.status = "FAIL"
        $auditResults.AccountSecurity.LocalGuestAccount.recommendations += $localUserAudit.Value.GuestRecommandation.Enabled
        $auditResults.AccountSecurity.LocalGuestAccount.comments += "Guest default account is enabled."

    } else {
        Add-ToLog -Message $localUserAudit.Value.GuestRecommandation.Disabled -ForegroundColor Green
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
    Add-ToLog -Message "`n[+] Audit du privilege $($audit.Privilege) :" -ForegroundColor Gray
    $auditResults.AccountSecurity.Privilege = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }
    $auditResults.AccountSecurity.Privilege.recommendations += $audit.Recommendation
    if ($audit.Configured) {
        Add-ToLog -Message "Privilege configure : $($audit.Privilege)" -ForegroundColor Yellow
        Add-ToLog -Message "Assigne a : $($audit.AssignedTo -join ', ')" -ForegroundColor Gray
        Add-ToLog -Message "Administrateurs presents : $($audit.IsAdminPresent)" -ForegroundColor Gray
        Add-ToLog -Message "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
        $auditResults.AccountSecurity.Privilege.status = "WARNING"
        $auditResults.AccountSecurity.Privilege.comments += "Privilege $($audit.Privilege), assigned to $($audit.AssignedTo -join ', '). Admins present: $($audit.IsAdminPresent)."
    } else {
        Add-ToLog -Message "Privilege non configure." -ForegroundColor Green
        Add-ToLog -Message "Recommandation : $($audit.Recommendation)" -ForegroundColor Yellow
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
Add-ToLog -Message "`n[+] Audit de la configuration LAPS :" -Foregroundcolor Gray

if ($lapsaudit){

    if ($context.isDomainjoined -eq $true) {
        $auditResults.AccountSecurity.LAPS.recommendations += $lapsAudit.Recommendation

        # Affichage dynamique selon le resultat
        switch ($lapsAudit.Status) {
            "PASS" {
                Add-ToLog -Message "   [OK] $($lapsAudit.DetectedMethods)" -ForegroundColor Green
                # Si on a un warning mineur (ex: Legacy + Modern en meme temps)
                if ($lapsAudit.Recommendation -match "ATTENTION") {
                    Add-ToLog -Message "   $($lapsAudit.Recommendation)" -ForegroundColor Magenta
                }
                $auditResults.AccountSecurity.LAPS.status = "PASS"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS configuration is compliant."
            }
            "WARNING" {
                # Cas specifique Legacy seul
                Add-ToLog -Message "   [OBSOLETE] $($lapsAudit.DetectedMethods)" -ForegroundColor Orange
                Add-ToLog -Message "   -> $($lapsAudit.Recommendation)" -ForegroundColor Yellow
                $auditResults.AccountSecurity.LAPS.status = "WARNING"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS configuration uses obsolete methods."
            }
            "FAIL" {
                Add-ToLog -Message "   [ALERTE] $($lapsAudit.Recommendation)" -ForegroundColor Red
                $auditResults.AccountSecurity.LAPS.status = "FAIL"
                $auditResults.AccountSecurity.LAPS.comments += "LAPS is not configured."
            }
        }

    }
    else {
        Add-ToLog -Message "`rLa machine n'est pas jointe a un domaine. LAPS n'est pas auditable" -ForegroundColor Magenta
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

if ($context.isDomainjoined -eq $true){
    $auditResults.AccountSecurity.ADPasswordPolicy = @{
        status = ""
        automatable = $false
        recommendations = @()
        comments = ""
    }

    $adPasswordPolicy = Get-ADPolPassAudit

    if ($adPasswordPolicy -and $context.isDomainjoined -eq $true) {
        $auditResults.AccountSecurity.ADPasswordPolicy.status = "PASS"

        Add-ToLog -Message "`n[+] Audit des politiques de mots de passe Active Directory :" -Foregroundcolor Gray
        try {
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Password Policy length must be at least $($adPasswordPolicy.MinLengthReco)"
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Password Complexity must be $($adPasswordPolicy.ComplexityReco)"
            $auditResults.AccountSecurity.ADPasswordPolicy.recommendations += "AD Account Lockout Policy must be $($adPasswordPolicy.LockoutReco)"
                
            # Affichage Longueur
            if ($adPasswordPolicy.MinLengthStatus -eq "FAIL") {
                Add-ToLog -Message "   [LONGUEUR]   [ALERTE] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password length requirement is not met."
            } else {
                Add-ToLog -Message "   [LONGUEUR]   [OK] $($adPasswordPolicy.MinLengthReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password length requirement is met."
            }

            # Affichage Complexite
            if ($adPasswordPolicy.ComplexityStatus -eq "FAIL") {
                Add-ToLog -Message "   [COMPLEXITE] [ALERTE] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password complexity requirement is not met."
            } else {
                Add-ToLog -Message "   [COMPLEXITE] [OK] $($adPasswordPolicy.ComplexityReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Password complexity requirement is met."
            }

            # Affichage Verrouillage
            if ($adPasswordPolicy.LockoutStatus -eq "FAIL") {
                Add-ToLog -Message "   [BLOCAGE]    [ALERTE] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.ADPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is not met."
            } elseif ($adPasswordPolicy.LockoutStatus -eq "WARNING") {
                Add-ToLog -Message "   [BLOCAGE]    [MOYEN] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Magenta
                if ($auditResults.AccountSecurity.ADPasswordPolicy.status -ne "FAIL") {
                    $auditResults.AccountSecurity.ADPasswordPolicy.status = "WARNING"
                }
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is partially met."
            } else {
                Add-ToLog -Message "   [BLOCAGE]    [OK] $($adPasswordPolicy.LockoutReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.ADPasswordPolicy.comments += "AD Account lockout requirement is met."
            }
        }
        catch {
            Add-ToLog -Message "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe AD"
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

    Add-ToLog -Message "`n[+] Audit des politiques de mots de passe :" -Foregroundcolor Gray

    
    try {
        $passwordPolicy = Get-PolPassAudit

        if ($passwordPolicy){
            $auditResults.AccountSecurity.LocalPasswordPolicy.status = "PASS"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Password Policy length must be at least $($passwordPolicy.MinLengthReco)"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Password Complexity must be $($passwordPolicy.ComplexityReco)"
            $auditResults.AccountSecurity.LocalPasswordPolicy.recommendations += "Account Lockout Policy must be $($passwordPolicy.LockoutReco)"
                
            # Affichage Longueur
            if ($passwordPolicy.MinLengthStatus -eq "FAIL") {
                Add-ToLog -Message "   [LONGUEUR]   [ALERTE] $($passwordPolicy.MinLengthReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password length requirement is not met."
            } else {
                Add-ToLog -Message "   [LONGUEUR]   [OK] $($passwordPolicy.MinLengthReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password length requirement is met."
            }

            # Affichage Complexite
            if ($passwordPolicy.ComplexityStatus -eq "FAIL") {
                Add-ToLog -Message "   [COMPLEXITE] [ALERTE] $($passwordPolicy.ComplexityReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password complexity requirement is not met."
            } else {
                Add-ToLog -Message "   [COMPLEXITE] [OK] $($passwordPolicy.ComplexityReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Password complexity requirement is met."
            }

            # Affichage Verrouillage
            if ($passwordPolicy.LockoutStatus -eq "FAIL") {
                Add-ToLog -Message "   [BLOCAGE]    [ALERTE] $($passwordPolicy.LockoutReco)" -ForegroundColor Red
                $auditResults.AccountSecurity.LocalPasswordPolicy.status = "FAIL"
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is not met."
            } elseif ($passwordPolicy.LockoutStatus -eq "WARNING") {
                Add-ToLog -Message "   [BLOCAGE]    [MOYEN] $($passwordPolicy.LockoutReco)" -ForegroundColor Magenta
                if ($auditResults.AccountSecurity.LocalPasswordPolicy.status -ne "FAIL") {
                    $auditResults.AccountSecurity.LocalPasswordPolicy.status = "WARNING"
                }
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is partially met."
            } else {
                Add-ToLog -Message "   [BLOCAGE]    [OK] $($passwordPolicy.LockoutReco)" -ForegroundColor Green
                $auditResults.AccountSecurity.LocalPasswordPolicy.comments += "Account lockout requirement is met."
            }
        }
        
    } catch {
        Add-ToLog -Message "Erreur lors de l'affichage des resultats de l'audit de la politique de mot de passe"
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

Add-ToLog -Message "`n[+] Audit du niveau d'authentification :" -Foregroundcolor Gray
$authLevelAudit = Get-AuthenticationLevelAudit

if ($context.osRole -eq "Workstation" -and $context.isDomainjoined -eq $true) {
    $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Enable Windows Hello for Business via GPO or CSP."

    if ($authLevelAudit.GPO -eq $true) {
        Add-ToLog -Message "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via GPO."
    }
    if ($authLevelAudit.CSP -eq $true) {
        Add-ToLog -Message "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via CSP."
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Add-ToLog -Message "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is not enabled."
    }
} elseif ($context.osRole -eq "Workstation" -and $context.isDomainjoined -eq $false) {
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Consider using Windows Hello even in a no domain-joined environment."

    if ($authLevelAudit.Consumer -eq $true) {
        Add-ToLog -Message "   [OK] Windows Hello (Consumer/Local) est active." -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is enabled."
    } else {
        Add-ToLog -Message "   [ALERTE] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is not enabled."
    }
} elseif ($context.osRole -eq "Server" -and $context.isDomainjoined -eq $true) {
    $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Enable Windows Hello for Business via GPO or CSP."

    if ($authLevelAudit.GPO -eq $true) {
        Add-ToLog -Message "   [OK] Windows Hello for Business est active via : GPO" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via GPO."
    }
    if ($authLevelAudit.CSP -eq $true) {
        Add-ToLog -Message "   [OK] Windows Hello for Business est active via : CSP" -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is enabled via CSP."
    }
    if (($authLevelAudit.GPO -eq $false) -and ($authLevelAudit.CSP -eq $false)) {
        Add-ToLog -Message "   [ALERTE] Windows Hello for Business n'est pas active." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello for Business is not enabled."
    }
} elseif ($context.osRole -eq "Server" -and $context.isDomainjoined -eq $false) {
    $auditResults.AccountSecurity.AuthentificationLevel.recommendations += "Disable Windows Hello (Consumer/Local) on servers."

    if ($authLevelAudit.Consumer -eq $true) {
        Add-ToLog -Message "   [ALERTE] Windows Hello (Consumer/Local) est active. Il est plutot recommande de desactiver cette fonctionnalite sur les serveurs." -ForegroundColor Red
        $auditResults.AccountSecurity.AuthentificationLevel.status = "FAIL"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is enabled on a server."
    } else {
        Add-ToLog -Message "   [OK] Windows Hello (Consumer/Local) n'est pas active." -ForegroundColor Green
        $auditResults.AccountSecurity.AuthentificationLevel.status = "PASS"
        $auditResults.AccountSecurity.AuthentificationLevel.comments += "Windows Hello (Consumer/Local) is not enabled on the server."
    }
} else {
    Add-ToLog -Message "   [INFORMATION] Le niveau d'authentification n'a pas pu etre audite dans ce contexte." -ForegroundColor Yellow
}

Merge-AuditResults -Section $auditResults.AccountSecurity.AuthentificationLevel -AuditData $authLevelAudit

########## UAC Audit ##########
$auditResults.AccountSecurity.UAC = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Add-ToLog -Message "`n[+] Audit de la configuration de l'UAC :" -Foregroundcolor Gray
$uacAudit = Get-UACAudit

try {
    $auditResults.AccountSecurity.UAC.status = "PASS"
    $auditResults.AccountSecurity.UAC.recommendations += "Enable UAC to enhance security."
    $auditResults.AccountSecurity.UAC.recommendations += "Enable Administrator Token Filtering to enhance security."
    $auditResults.AccountSecurity.UAC.recommendations += "Enable Local Account Token Filter Policy to prevent non-administrator network access."

    if ($uacAudit.UACEnabled -eq 1) {
        Add-ToLog -Message "   [OK] L'UAC est active." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "UAC is enabled."
    } else {
        Add-ToLog -Message "   [ALERTE] L'UAC est desactive." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "UAC is disabled."
    }

    if ($uacAudit.FilterAdministratorToken -eq 1) {
        Add-ToLog -Message "   [OK] Le filtrage du token administrateur est active." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "Administrator Token Filtering is enabled."
    } else {
        Add-ToLog -Message "   [ALERTE] Le filtrage du token administrateur est desactive." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "Administrator Token Filtering is disabled." 
    }

    if ($uacAudit.LocalAccountTokenFilterPolicy -eq 1) {
        Add-ToLog -Message "   [OK] La politique de filtrage des tokens pour les comptes locaux est activee." -ForegroundColor Red
        $auditResults.AccountSecurity.UAC.status = "FAIL"
        $auditResults.AccountSecurity.UAC.comments += "Local Account Token Filter Policy is enabled."
    } else {
        Add-ToLog -Message "   [OK] La politique de filtrage des tokens pour les comptes locaux est desactivee." -ForegroundColor Green
        $auditResults.AccountSecurity.UAC.comments += "Local Account Token Filter Policy is disabled."
    }
}
catch {
    Add-ToLog -Message "Erreur lors de l'affichage des resultats de l'audit UAC"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.UAC -AuditData $uacAudit


########## JEA Audit ##########
$auditResults.AccountSecurity.JEA = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}

Add-ToLog -Message "`n[+] Audit de la configuration JEA :" -Foregroundcolor Gray
$JEAAudit = Get-JEAAudit
try {
    $auditResults.AccountSecurity.JEA.recommendations += $JEAAudit.Recommandation

    if ($JEAAudit.WinRmState -eq 'NotInstalled'){
        Add-ToLog -Message "   [INFORMATION] WinRM n'est pas installe. JEA ne peut pas etre configure." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.comments += "WinRM is not installed; JEA cannot be used."
    } elseif ($JEAAudit.WinRmState -eq 'Stopped') {
        Add-ToLog -Message "   [ALERTE] WinRM est installe mais arrete. JEA ne peut pas etre utilise tant que WinRM n'est pas demarre." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.status = "FAIL"
        $auditResults.AccountSecurity.JEA.comments += "WinRM is stopped; JEA cannot be used."
    } elseif ($JEAAudit.HasJEASessionConfig -eq $true){
        Add-ToLog -Message "   [OK] Des endpoints JEA sont configures sur cette machine." -ForegroundColor Green
        Add-ToLog -Message "       $($JEAAudit.Recommandation)" -ForegroundColor Gray
        $auditResults.AccountSecurity.JEA.status = "PASS"
        $auditResults.AccountSecurity.JEA.comments += "JEA endpoints are configured."
    } elseif ($JEAAudit.HasJEASessionConfig -eq $false){
        Add-ToLog -Message "   [ALERTE] WinRM est fonctionnel mais aucun endpoint JEA n'est configure." -ForegroundColor Red
        $auditResults.AccountSecurity.JEA.status = "FAIL"
        $auditResults.AccountSecurity.JEA.comments += "WinRM is running; No JEA endpoints are configured."
    } else {
        Write-Error "   [ERREUR] Impossible d'auditer la configuration JEA." -ForegroundColor Red
    }
} catch {
    Add-ToLog -Message "Erreur lors de l'affichage des resultats de l'audit JEA"
}

Merge-AuditResults -Section $auditResults.AccountSecurity.JEA -AuditData $JEAAudit


########## Local Groups Audit ##########
$auditResults.AccountSecurity.LocalGroups = @{
    status = ""
    automatable = $false
    recommendations = @()
    comments = ""
}
Add-ToLog -Message "`n[+] Audit des groupes locaux :" -Foregroundcolor Gray
$groupsAudit = Get-GroupsAudit

Add-ToLog -Message $groupsAudit.GetType()

if ($groupsAudit) {
    $auditResults.AccountSecurity.LocalGroups.status = "PASS"
    $auditResults.AccountSecurity.LocalGroups.recommendations += "A group should have at least one member. Verify local groups that have more than 3 members. Verify for unauthorized users."

    foreach ($group in $groupsAudit) {
        Add-ToLog -Message "`nGroupe : $($group.GroupName)" -ForegroundColor Cyan
        if ($group.Members -eq 0) {
            Add-ToLog -Message "   Aucun membre dans ce groupe." -ForegroundColor Yellow
            $auditResults.AccountSecurity.LocalGroups.status = "WARNING"
            $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has no members. Add complexity and increase attack surface."
        } else {
            Add-ToLog -Message "   Membres : $($group.Members -join ', ')" -ForegroundColor Yellow
            # A voir je trouve que c'est un peu trop restreint comme alerte
            if ($group.MembersCount -gt 3) {
                Add-ToLog -Message "   [ALERTE] Ce groupe contient un grand nombre de membres ($($group.MembersCount)). Verifiez qu'il n'y a pas d'utilisateurs non autorises." -ForegroundColor Red
                $auditResults.AccountSecurity.LocalGroups.status = "FAIL"
                $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has $($group.MembersCount) members. Verify for unauthorized users."
            } elseif ( $group.MembersCount -gt 1) {
                Add-ToLog -Message "   [ATTENTION] Ce groupe contient plusieurs membres ($($group.MembersCount)). Verifiez qu'il n'y a pas d'utilisateurs non autorises." -ForegroundColor Yellow
                $auditResults.AccountSecurity.LocalGroups.status = "WARNING"
                $auditResults.AccountSecurity.LocalGroups.comments += "The local group '$($group.GroupName)' has $($group.MembersCount) members. Verify for unauthorized users."
            } else {
                Add-ToLog -Message "   [OK] Nombre de membres dans ce groupe : $($group.MembersCount)" -ForegroundColor Green
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

Add-ToLog -Message "`n[+] Audit des partages SMB :" -Foregroundcolor Gray
$smbSharesAudit = Get-SMBSharesAudit

if ($smbSharesAudit) {
    $auditResults.AccountSecurity.SMBShares.recommendations += "Avoid using 'Everyone' group on SMB shares. Review share permissions and NTFS permissions for 'Everyone' group."
    $smbSharesAudit | ForEach-Object {
        $share = $_
        $sharesAccess = Get-SmbShareAccess -Name $share.Name
        $user = if ($_.AccountName -eq 'Tout le monde') {'Tout le monde'} else {'Everyone'}
        $sharesAccess | Where-Object { $_.AccountName -eq $user -and $_.AccessControlType -eq 'Allow' } | ForEach-Object {
            Add-ToLog -Message "`nAttention : Le partage SMB '"$($share.Name)"' est accessible par 'Tout le monde'. Chemin du partage : "$($share.Path) -ForegroundColor Red
            Add-ToLog -Message "Verification des droits NTFS du groupe 'Tout le monde' sur le repertoire partage..." -ForegroundColor Yellow
            $NTFSAudit = Get-NTFSAudit -Path $share.Path -User $user
            if ($NTFSAudit.IsFullControl -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                Add-ToLog -Message "Le groupe 'Tout le monde' dispose de droits Full Control sur le repertoire partage." -ForegroundColor Red
                Add-ToLog -Message "Le compte invite est active sur ce systeme, le partage est accessible sans mot de passe" -ForegroundColor Red
                $auditResults.AccountSecurity.SMBShares.status = "FAIL"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has Full Control on the SMB share '$($share.Name)'. Guest account is enabled, allowing unauthenticated access."
            } elseif ($NTFSAudit.CanWrite -eq $true -and $NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                Add-ToLog -Message "Le groupe 'Tout le monde' dispose de droits en lecture et ecriture sur le repertoire partage." -ForegroundColor Red
                Add-ToLog -Message "Le compte invite est active sur ce systeme, le partage est accessible en lecture ecriture sans mot de passe" -ForegroundColor Red
                $auditResults.AccountSecurity.SMBShares.status = "FAIL"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has Read and Write access on the SMB share '$($share.Name)'. Guest account is enabled, allowing unauthenticated access."
            } elseif ($NTFSAudit.CanWrite -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                Add-ToLog -Message "Le groupe 'Tout le monde' dispose de droits en ecriture sur le repertoire partage." -ForegroundColor Red
                Add-ToLog -Message "Le compte invite est active sur ce systeme, le partage est accessible en ecriture sans mot de passe" -ForegroundColor Red
                $auditResults.AccountSecurity.SMBShares.status = "FAIL"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has Write access on the SMB share '$($share.Name)'. Guest account is enabled, allowing unauthenticated access."
            } elseif ($NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                Add-ToLog -Message "Le groupe 'Tout le monde' dispose de droits en lecture sur le repertoire partage." -ForegroundColor Yellow
                Add-ToLog -Message "Le compte invite est active sur ce systeme, le partage est accessible en lecture sans mot de passe" -ForegroundColor Yellow
                $auditResults.AccountSecurity.SMBShares.status = "WARNING"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has Read access on the SMB share '$($share.Name)'. Guest account is enabled, allowing unauthenticated access."
            } elseif ($NTFSAudit.RawRights -eq 0 -and $localUserAudit.GuestEnabled -eq $true) {
                Add-ToLog -Message "Le groupe 'Tout le monde' dispose de droits personnalises sur le repertoire partage." -ForegroundColor Yellow
                Add-ToLog -Message "Le compte invite est active sur ce systeme, le partage est possiblement accessible sans mot de passe" -ForegroundColor Yellow
                $auditResults.AccountSecurity.SMBShares.status = "WARNING"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has custom rights on the SMB share '$($share.Name)'. Guest account is enabled, possibly allowing unauthenticated access."
            } elseif ($localUserAudit.GuestEnabled -eq $false) {
                Add-ToLog -Message "Le compte invite est desactive sur ce systeme, le partage n'est pas accessible sans mot de passe." -ForegroundColor Green
                $auditResults.AccountSecurity.SMBShares.status = "PASS"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has access on the SMB share '$($share.Name)', but the Guest account is disabled, preventing unauthenticated access."
            } else {
                Add-ToLog -Message "Le groupe 'Tout le monde' ne dispose pas de droits de lecture ou ecriture sur le repertoire partage." -ForegroundColor Green
                $auditResults.AccountSecurity.SMBShares.status = "PASS"
                $auditResults.AccountSecurity.SMBShares.comments += "The 'Everyone' group has no Read or Write access on the SMB share '$($share.Name)'."
            }
        }
    }
}

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
Add-ToLog -Message "`n[+] Audit des services RDP :" -ForegroundColor Gray
$rdpAudit = Get-RDPAudit

if ($rdpAudit -and $rdpAudit.Value) {
    $r = $rdpAudit.Value

    if ($r.RDPEnabled -eq $true) {
        Add-ToLog -Message "   [ENABLED] RDP est active sur cette machine." -ForegroundColor Red
        $auditResults.ServicesAndApplications.RDP.status = "FAIL"
        $auditResults.ServicesAndApplications.RDP.comments += "RDP is enabled."
    }
    else {
        Add-ToLog -Message "   [DISABLED] RDP est desactive au niveau OS." -ForegroundColor Green
        $auditResults.ServicesAndApplications.RDP.status = "PASS"
        $auditResults.ServicesAndApplications.RDP.comments += "RDP is disabled. "
    }

    Add-ToLog -Message "   [ADMIN RESTREINT] DisableRestrictedAdmin : $($r.DisableRestrictedAdmin)" -ForegroundColor Gray
    Add-ToLog -Message "   [CHIFFREMENT] MinEncryptionLevel : $($r.MinEncryptionLevel)" -ForegroundColor Gray
    Add-ToLog -Message "   [COUCHE DE SECURITE] SecurityLayer : $($r.SecurityLayer)" -ForegroundColor Gray
    Add-ToLog -Message "   [NLA] UserAuthentication : $($r.UserAuthentication)" -ForegroundColor Gray

    if ($r.fEncryptRPCTraffic -eq $true) {
        Add-ToLog -Message "   [RPC] fEncryptRPCTraffic : Enabled" -ForegroundColor Green
        $auditResults.ServicesAndApplications.RDP.comments += "RPC traffic encryption is enabled. "
    } else {
        Add-ToLog -Message "   [RPC] fEncryptRPCTraffic : Disabled" -ForegroundColor Red
        $auditResults.ServicesAndApplications.RDP.comments += "RPC traffic encryption is disabled. "
        if ($auditResults.ServicesAndApplications.RDP.status -ne "FAIL") {
            $auditResults.ServicesAndApplications.RDP.status = "WARNING"
        }
    }

    if ($r.Recommendation) {
        Add-ToLog -Message "`n   Recommandation : $($r.Recommendation)" -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.RDP.recommendations += "$($r.Recommendation) | "
    }

    if ($rdpAudit.Xml) {
        Add-ToLog -Message "`n   Actions proposees :" -ForegroundColor Gray
        foreach ($item in $rdpAudit.Xml) {
            Add-ToLog -Message "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
            Add-ToLog -Message "         Commande : $($item.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit WinRM :" -ForegroundColor Gray
try {
    $winrmAudit = Get-WinRMAudit

    if (-not $winrmAudit.WinRmEnabled) {
        Add-ToLog -Message "   [INACTIF] WinRM n'est pas installe ou le service est arrete." -ForegroundColor Magenta
        Add-ToLog -Message "   Recommandation :" -ForegroundColor Yellow
        foreach ($r in $winrmAudit.Recommendations) { 
            Add-ToLog -Message "      - $r" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.WinRM.recommendations += "$r | "
        }
        $auditResults.ServicesAndApplications.WinRM.status = "FAIL"
        $auditResults.ServicesAndApplications.WinRM.comments += "WinRM is not enabled. "
    }
    else {
        Add-ToLog -Message "   [ACTIF] WinRM est active." -ForegroundColor Yellow
        Add-ToLog -Message "   [TRANSPORT] ListenerTransport : $($winrmAudit.ListenerTransport)" -ForegroundColor Gray
        Add-ToLog -Message "   [ECOUTE] ListeningOn        : $($winrmAudit.ListeningOn)" -ForegroundColor Gray
        Add-ToLog -Message "   [FILTRES IP] IPv4 : $($winrmAudit.IPv4Filter)    IPv6 : $($winrmAudit.IPv6Filter)" -ForegroundColor Gray
        
        $auditResults.ServicesAndApplications.WinRM.status = "PASS"
        $auditResults.ServicesAndApplications.WinRM.comments += "WinRM is enabled. "

        if ($winrmAudit.ServiceAuth) {
            Add-ToLog -Message "   [AUTH SERVICE] Basic : $($winrmAudit.ServiceAuth.Basic)    Unencrypted : $($winrmAudit.ServiceAuth.Unencrypted)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.WinRM.comments += "Service Auth Basic: $($winrmAudit.ServiceAuth.Basic), Unencrypted: $($winrmAudit.ServiceAuth.Unencrypted). "
        }
        if ($winrmAudit.ClientAuth) {
            Add-ToLog -Message "   [AUTH CLIENT]  Basic : $($winrmAudit.ClientAuth.Basic)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.WinRM.comments += "Client Auth Basic: $($winrmAudit.ClientAuth.Basic). "
        }

        if ($winrmAudit.RmUsersNotAdmins) {
            Add-ToLog -Message "   [UTILISATEURS] Comptes dans Remote Management Users (non-admin) : $($winrmAudit.RmUsersNotAdmins -join ', ')" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.WinRM.comments += "Non-admin Remote Management Users: $($winrmAudit.RmUsersNotAdmins -join ', '). "
        }

        if ($winrmAudit.Recommendations) {
            Add-ToLog -Message "`n   Recommandations :" -ForegroundColor Yellow
            foreach ($rec in $winrmAudit.Recommendations) {
                Add-ToLog -Message "      - $rec" -ForegroundColor Yellow
                $auditResults.ServicesAndApplications.WinRM.recommendations += "$rec | "
            }
        } else {
            Add-ToLog -Message "   [OK] Configuration WinRM conforme aux bonnes pratiques detectee." -ForegroundColor Green
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
Add-ToLog -Message "`n[+] Audit SMB :" -ForegroundColor Gray

try {
    $smbAudit = Get-SMBAudit

    if ($smbAudit -and $smbAudit.Value) {
        $s = $smbAudit.Value
        $smbOk = $true

        # Affichage du statut SMBv1
        if ($s.SMBv1State -eq $true) {
            Add-ToLog -Message "   [SMBv1] [ALERTE] SMBv1 est active. Il est recommande de le desactiver." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv1 is enabled. "
            $smbOk = $false
        } else {
            Add-ToLog -Message "   [SMBv1] [OK] SMBv1 est desactive." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv1 is disabled. "
        }

        # Affichage du statut SMBv2/3
        if ($s.SMBv2State -eq $true) {
            Add-ToLog -Message "   [SMBv2/3] [OK] SMBv2/3 est active." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv2/3 is enabled. "
        } else {
            Add-ToLog -Message "   [SMBv2/3] [ALERTE] SMBv2/3 est desactive." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMBv2/3 is disabled. "
            $smbOk = $false
        }

        # Affichage du statut de la signature SMB
        if ($s.RequireSecuritySignature -eq $true) {
            Add-ToLog -Message "   [SIGNING] [OK] La signature de securite SMB est requise." -ForegroundColor Green
            $auditResults.ServicesAndApplications.SMB.comments += "SMB signing is required. "
        } else {
            Add-ToLog -Message "   [SIGNING] [ALERTE] La signature de securite SMB n'est pas requise." -ForegroundColor Red
            $auditResults.ServicesAndApplications.SMB.comments += "SMB signing is not required. "
            $smbOk = $false
        }

        if ($s.Comment) {
            Add-ToLog -Message "`n   Details : $($s.Comment)" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.SMB.comments += "$($s.Comment) "
        }

        if ($s.Recommendation) {
            Add-ToLog -Message "`n   Recommandation : $($s.Recommendation)" -ForegroundColor Yellow
            $auditResults.ServicesAndApplications.SMB.recommendations += "$($s.Recommendation) | "
        }

        # Affichage des actions proposees
        if ($smbAudit.Xml) {
            Add-ToLog -Message "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $smbAudit.Xml) {
                Add-ToLog -Message "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Add-ToLog -Message "         Commande : $($item.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit des mises a jour et version OS :" -ForegroundColor Gray
try {
    $osInfo = Get-OSVersionInfo
    if ($osInfo) {
        Add-ToLog -Message "`n[OS] $($osInfo.Caption) - Version $($osInfo.Version) (Full: $($osInfo.FullVersion))" -ForegroundColor Cyan
        $auditResults.ServicesAndApplications.Updates.comments += "OS: $($osInfo.Caption), Version: $($osInfo.Version). "
        
        if ($osInfo.InstallDate) {
            $installDate = [datetime]$osInfo.InstallDate
            Add-ToLog -Message "Build: $($osInfo.BuildNumber)   Installe le: $($installDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.Updates.comments += "Build: $($osInfo.BuildNumber), Installed: $($installDate.ToString('yyyy-MM-dd HH:mm')). "
        } else {
            Add-ToLog -Message "Build: $($osInfo.BuildNumber)   InstallDate: Non disponible" -ForegroundColor Gray
            $auditResults.ServicesAndApplications.Updates.comments += "Build: $($osInfo.BuildNumber). "
        }
        
        $auditResults.ServicesAndApplications.Updates.status = "PASS"
        $auditResults.ServicesAndApplications.Updates.recommendations += "Keep the system updated with latest security patches. "
    }

    $updateSource = Get-UpdateSource
    Add-ToLog -Message "`n[Source de mises a jour] $updateSource" -ForegroundColor Gray
    $auditResults.ServicesAndApplications.Updates.comments += "Update source: $updateSource. "

    $kbList = Get-InstalledKB
    if ($kbList) {
        Add-ToLog -Message "`n[+] Dernieres mises a jour installees (10 dernieres) :" -ForegroundColor Gray
        $kbList | Select-Object -First 10 | Format-Table HotFixID, Description, @{Name='InstalledOn';Expression={ ($_.InstalledOn -as [datetime]).ToString('yyyy-MM-dd') }}, InstalledBy -AutoSize
        $auditResults.ServicesAndApplications.Updates.comments += "$($kbList.Count) KB updates found. "
    } else {
        Add-ToLog -Message "Aucune mise a jour detectee via Get-HotFix" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit des applications installees :" -ForegroundColor Gray
try {
    $apps = Get-InstalledApplications

    if ($apps) {
        Add-ToLog -Message "   [INFO] Nombre d'applications detectees : $(($apps | Measure-Object).Count)" -ForegroundColor Gray
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "$($apps.Count) applications detected. "
        $apps | Select-Object Name, Version, Publisher, InstallLocation |
            Sort-Object Name |
            Format-Table -AutoSize
        $auditResults.ServicesAndApplications.InstalledApplications.status = "PASS"
    } else {
        Add-ToLog -Message "   [INFO] Aucune application installee detectee." -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "No installed applications detected. "
        $auditResults.ServicesAndApplications.InstalledApplications.status = "PASS"
    }

    # Verification des mises a jour applicatives via WinGet (si disponible)
    $appUpgrades = Get-AppUpgrade -ErrorAction SilentlyContinue
    if ($appUpgrades) {
        Add-ToLog -Message "`n   [Mises a jour disponibles via WinGet] :" -ForegroundColor Yellow
        $appUpgrades |
            Select-Object Name, InstalledVersion, @{Name='Available';Expression={$_.AvailableVersions -join ','}} |
            Format-Table -AutoSize
        Add-ToLog -Message "   Recommandation : utiliser `winget upgrade --all` pour mettre a jour les applications prises en charge." -ForegroundColor Yellow
        $auditResults.ServicesAndApplications.InstalledApplications.recommendations += "If winget installed, consider to use 'winget upgrade --name ...' to update supported applications. If not installed, please verify manually"
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "$($appUpgrades.Count) application updates available via WinGet. "
        $auditResults.ServicesAndApplications.InstalledApplications.status = "WARNING"
    } elseif ($null -eq $appUpgrades) {
        Add-ToLog -Message "   [INFO] WinGet non disponible ou aucune donnee de mise a jour." -ForegroundColor Gray
        $auditResults.ServicesAndApplications.InstalledApplications.comments += "WinGet not available or no update data. "
    } else {
        Add-ToLog -Message "   [OK] Aucune mise a jour applicative detectee via WinGet." -ForegroundColor Green
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

Add-ToLog -Message "`n[+] Audit de la configuration IPv6 :" -ForegroundColor Gray
$ipv6Audit = Get-IPv6Status

if ($ipv6Audit -and $ipv6Audit.Count -gt 0) {
    $auditResults.NetworkSecurity.IPv6.status = "PASS"
    $ipv6Recs = @()
    foreach ($adapter in $ipv6Audit) {
        if ($adapter.IPv6Enabled -eq $true) {
            Add-ToLog -Message "   [ENABLED] Adapter: $($adapter.Adapter) - IPv6 is enabled." -ForegroundColor Red
            Add-ToLog -Message "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.IPv6.status = "FAIL"
            $ipv6Recs += $adapter.Recommendation
            $auditResults.NetworkSecurity.IPv6.comments += "IPv6 is enabled on adapter $($adapter.Adapter). "
        } else {
            Add-ToLog -Message "   [DISABLED] Adapter: $($adapter.Adapter) - IPv6 is disabled." -ForegroundColor Green
            Add-ToLog -Message "       Recommendation: $($adapter.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de la configuration LLMNR :" -ForegroundColor Gray
$llmnrAudit = Get-LLMNRState

if (-not $llmnrAudit.Value) {
    Add-ToLog -Message "   [DEFAULT] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Add-ToLog -Message "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
    $auditResults.NetworkSecurity.LLMNR.status = "FAIL"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is enabled (default). "
} elseif ($llmnrAudit.Value -eq 1) {
    Add-ToLog -Message "   [ENABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Red
    Add-ToLog -Message "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
    $auditResults.NetworkSecurity.LLMNR.status = "FAIL"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is enabled. "
} elseif ($llmnrAudit.Value -eq 0) {
    Add-ToLog -Message "   [DISABLED] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Green
    Add-ToLog -Message "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Green
    $auditResults.NetworkSecurity.LLMNR.status = "PASS"
    $auditResults.NetworkSecurity.LLMNR.comments += "LLMNR is disabled. "
} else {
    Add-ToLog -Message "   [UNKNOWN] - $($llmnrAudit.LLMNR_Status)" -ForegroundColor Yellow
    Add-ToLog -Message "       Recommendation: $($llmnrAudit.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de la configuration NetBIOS :" -ForegroundColor Gray
$netbiosAudit = Get-NetBiosInfo

if ($netbiosAudit) {
    $hasIssue = $false
    $netbiosRecs = @()
    foreach ($adapter in $netbiosAudit) {
        Add-ToLog -Message "`n   Interface: $($adapter.Interface)" -ForegroundColor Cyan
        Add-ToLog -Message "   Statut NetBIOS: $($adapter.NetBIOS_Status)" -ForegroundColor Gray
        Add-ToLog -Message "   Code TcpipNetbiosOptions: $($adapter.TcpipNetbiosOptions)" -ForegroundColor Gray
        
        # Affichage conditionnel selon le statut
        switch ($adapter.TcpipNetbiosOptions) {
            2 {
                Add-ToLog -Message "   [OK] $($adapter.Recommendation)" -ForegroundColor Green
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is disabled on adapter $($adapter.Interface). "
            }
            1 {
                Add-ToLog -Message "   [ALERTE] $($adapter.Recommendation)" -ForegroundColor Red
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is enabled via DHCP on adapter $($adapter.Interface). "
                $hasIssue = $true
            }
            0 {
                Add-ToLog -Message "   [MOYEN] $($adapter.Recommendation)" -ForegroundColor Red
                $netbiosRecs += $adapter.Recommendation
                $auditResults.NetworkSecurity.NetBIOS.comments += "NetBIOS is enabled on adapter $($adapter.Interface). "
                $hasIssue = $true
            }
            default {
                Add-ToLog -Message "   [INFORMATION] $($adapter.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit du pare-feu (Windows Firewall) :" -ForegroundColor Gray
$fwAudit = Get-FirewallAudit

if ($fwAudit) {

    # Etat du service Firewall
    if ($fwAudit.FirewallServiceStatus -eq 'NotFound') {
        Add-ToLog -Message "   [INFORMATION] Le service Windows Firewall (mpssvc) n'a pas ete trouve." -ForegroundColor Red
        Add-ToLog -Message "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
        $auditResults.NetworkSecurity.Firewall.status = "FAIL"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service not found. "
    }
    elseif (-not $fwAudit.FirewallServiceRunning) {
        Add-ToLog -Message "   [ALERTE] Le service Windows Firewall existe mais n'est pas demarre : $($fwAudit.FirewallServiceStatus)" -ForegroundColor Red
        Add-ToLog -Message "       Recommandation : $($fwAudit.GlobalRecommendations -join '; ')" -ForegroundColor Yellow
        $auditResults.NetworkSecurity.Firewall.status = "FAIL"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service not running: $($fwAudit.FirewallServiceStatus). "
    }
    else {
        Add-ToLog -Message "   [OK] Le service Windows Firewall est en cours d'execution." -ForegroundColor Green
        Add-ToLog -Message "   [PROFIL ACTIF] : $($fwAudit.ActiveProfile)" -ForegroundColor Gray
        $auditResults.NetworkSecurity.Firewall.status = "PASS"
        $auditResults.NetworkSecurity.Firewall.comments += "Windows Firewall service is running on active profile: $($fwAudit.ActiveProfile). "
    }

    # Details et recommandations RDP
    $fwRecs = @()
    if ($fwAudit.RdpRuleDetails) {
        Add-ToLog -Message "`n   Regles RDP detectees (nom / LocalAddress / RemoteAddress) :" -ForegroundColor Gray
        foreach ($r in $fwAudit.RdpRuleDetails) {
            Add-ToLog -Message "      - $($r.Name)    Local: $($r.LocalAddress)    Remote: $($r.RemoteAddress)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.Firewall.comments += "RDP rule detected: $($r.Name). "
        }

        if ($fwAudit.RdpRecommendations) {
            Add-ToLog -Message "`n   Recommandations RDP :" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) { 
                Add-ToLog -Message "      - $rec" -ForegroundColor Yellow
                $fwRecs += $rec
            }
        }
    }
    else {
        Add-ToLog -Message "`n   [INFO] Aucune regle RDP activee detectee." -ForegroundColor Gray
        if ($fwAudit.RdpRecommendations -and ($fwAudit.RdpRecommendations | Measure-Object).Count -gt 0) {
            Add-ToLog -Message "   Recommandation : $($fwAudit.RdpRecommendations -join '; ')" -ForegroundColor Yellow
            foreach ($rec in $fwAudit.RdpRecommendations) {
                $fwRecs += $rec
            }
        }
    }

    # Recommandations globales
    if ($fwAudit.GlobalRecommendations -and ($fwAudit.GlobalRecommendations | Measure-Object).Count -gt 0) {
        Add-ToLog -Message "`n   Recommandations globales :" -ForegroundColor Yellow
        foreach ($g in $fwAudit.GlobalRecommendations) { 
            Add-ToLog -Message "      - $g" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit des connexions VPN :" -ForegroundColor Gray
$vpnStatus = Get-VPNStatus

if ($vpnStatus) {
    Add-ToLog -Message "   Description : $($vpnStatus.Description)" -ForegroundColor Gray

    if ($vpnStatus.HasVpnAdapters) {
        Add-ToLog -Message "`n   Interfaces VPN/TAP/TUN actives detectees :" -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.status = "WARNING"
        foreach ($a in $vpnStatus.Adapters) {
            Add-ToLog -Message "      - $($a.Name) | $($a.InterfaceDescription) | $($a.Status)" -ForegroundColor Yellow
            $auditResults.NetworkSecurity.VPN.comments += "VPN adapter detected: $($a.Name) ($($a.Status)). "
        }
        $auditResults.NetworkSecurity.VPN.recommendations += "Review VPN adapter configurations for security. | "
    } else {
        Add-ToLog -Message "   [INFO] Aucune interface VPN/TAP/TUN active detectee." -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.status = "PASS"
        $auditResults.NetworkSecurity.VPN.comments += "No active VPN/TAP/TUN adapters detected. "
    }

    if ($vpnStatus.HasVpnProfiles) {
        Add-ToLog -Message "`n   Profils VPN configures : $($vpnStatus.VpnProfiles.Count)" -ForegroundColor Gray
        $auditResults.NetworkSecurity.VPN.comments += "$($vpnStatus.VpnProfiles.Count) VPN profile(s) configured. "
        if ($vpnStatus.HasActiveVpnProfiles) {
            Add-ToLog -Message "   Profils VPN connectes : $($vpnStatus.ActiveVpnProfiles.Count)" -ForegroundColor Green
            $auditResults.NetworkSecurity.VPN.comments += "$($vpnStatus.ActiveVpnProfiles.Count) VPN profile(s) connected. "
            if ([string]::IsNullOrWhiteSpace($auditResults.NetworkSecurity.VPN.status)) {
                $auditResults.NetworkSecurity.VPN.status = "PASS"
            }
        } else {
            Add-ToLog -Message "   Aucun profil VPN actuellement connecte." -ForegroundColor Yellow
            $auditResults.NetworkSecurity.VPN.comments += "No active VPN profiles connected. "
            if ([string]::IsNullOrWhiteSpace($auditResults.NetworkSecurity.VPN.status)) {
                $auditResults.NetworkSecurity.VPN.status = "PASS"
            }
        }
    } else {
        Add-ToLog -Message "   [INFO] Aucun profil VPN configure via le client Windows." -ForegroundColor Gray
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

Add-ToLog -Message "`n[+] Audit des fonctionnalites optionnelles (Windows Optional Features) :" -ForegroundColor Gray
try {
    $optFeatures = Get-OptionalFeaturesAudit

    if ($optFeatures) {
        Add-ToLog -Message "   [INFO] Nombre de fonctionnalites optionnelles activees : $(($optFeatures | Measure-Object).Count)" -ForegroundColor Gray

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
            Add-ToLog -Message "`n   [ATTENTION] Fonctions potentiellement dangereuses / exposees :" -ForegroundColor Yellow
            $auditResults.OSSecurity.OptionalFeatures.status = "FAIL"
            $featRecs = @()
            foreach ($f in $risky) {
                Add-ToLog -Message "      - $($f.FeatureName) : $($f.RiskNote)" -ForegroundColor Yellow
                Add-ToLog -Message "         Recommandation : $($f.Recommendation)" -ForegroundColor Yellow
                Add-ToLog -Message "         Action suggeree (exemple) : Disable-WindowsOptionalFeature -Online -FeatureName `"$($f.FeatureName)`" -NoRestart" -ForegroundColor DarkGray
                $featRecs += $f.Recommendation
                $auditResults.OSSecurity.OptionalFeatures.comments += "$($f.FeatureName): $($f.RiskNote). "
                $auditResults.OSSecurity.OptionalFeatures.automatable = $true
            }
            $auditResults.OSSecurity.OptionalFeatures.recommendations = ($featRecs | Select-Object -Unique) -join " | "
        } else {
            Add-ToLog -Message "   [OK] Aucune fonctionnalite optionnelle notablement risquee detectee." -ForegroundColor Green
            $auditResults.OSSecurity.OptionalFeatures.status = "PASS"
            $auditResults.OSSecurity.OptionalFeatures.comments += "No risky optional features detected. "
        }
    } else {
        Add-ToLog -Message "   [INFO] Aucune fonctionnalite optionnelle activee detectee." -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de la configuration AppLocker :" -ForegroundColor Gray
try {
    $appLockerState = Get-AppLockerState

    if ($appLockerState) {
        if ($appLockerState.AppLockerPresent) {
            # AppLocker est present
            if ($appLockerState.AnyRuleEnabled) {
                Add-ToLog -Message "   [OK] AppLocker est present et au moins une collection de regles est en mode Enforced." -ForegroundColor Green
                Add-ToLog -Message "       Statut : $($appLockerState.Comment)" -ForegroundColor Green
                $auditResults.OSSecurity.AppLocker.status = "PASS"
                $auditResults.OSSecurity.AppLocker.comments += "AppLocker is present and at least one rule collection is in Enforced mode. $($appLockerState.Comment). "
            } else {
                Add-ToLog -Message "   [INFO] AppLocker est present mais aucune collection de regles n'est en mode Enforced." -ForegroundColor Yellow
                Add-ToLog -Message "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
                $auditResults.OSSecurity.AppLocker.status = "WARNING"
                $auditResults.OSSecurity.AppLocker.comments += "AppLocker is present but no rule collection is in Enforced mode. $($appLockerState.Comment). "
            }
        } else {
            # Aucune politique AppLocker effective
            Add-ToLog -Message "   [ALERTE] Aucune politique AppLocker effective detectee sur ce systeme." -ForegroundColor Red
            Add-ToLog -Message "       Statut : $($appLockerState.Comment)" -ForegroundColor Yellow
            $auditResults.OSSecurity.AppLocker.status = "FAIL"
            $auditResults.OSSecurity.AppLocker.comments += "No effective AppLocker policy detected. $($appLockerState.Comment). "
        }

        # Affichage de la recommandation
        Add-ToLog -Message "       Recommandation : $($appLockerState.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de la configuration SRP (Software Restriction Policies) :" -ForegroundColor Gray
try {
    $srpAudit = Get-SRPState

    if ($srpAudit) {
        $srpDetected = $false
        foreach ($srp in $srpAudit) {
            Add-ToLog -Message "`n   Scope: $($srp.Scope)" -ForegroundColor Cyan
            
            if ($srp.SRPPresent) {
                Add-ToLog -Message "   [DeTECTe] SRP est configure pour ce scope." -ForegroundColor Yellow
                $auditResults.OSSecurity.SRP.status = "PASS"
                $srpDetected = $true
                $auditResults.OSSecurity.SRP.comments += "SRP is configured for scope: $($srp.Scope). "
            } else {
                Add-ToLog -Message "   [ABSENT] Aucune SRP detectee pour ce scope." -ForegroundColor Green
                if (-not $srpDetected) { $auditResults.OSSecurity.SRP.status = "FAIL" }
                $auditResults.OSSecurity.SRP.comments += "No SRP for scope $($srp.Scope). "
            }
            
            Add-ToLog -Message "   Chemin du registre: $($srp.RegistryPath)" -ForegroundColor Gray
            Add-ToLog -Message "   Statut: $($srp.Comment)" -ForegroundColor Gray
            Add-ToLog -Message "   Recommandation: $($srp.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de l'etat des services antivirus :" -ForegroundColor Gray
$antivirusStatus = Get-ServerAntivirusStatus

if ($antivirusStatus) {
    $hasIssue = $false
    $avRecs = @()
    foreach ($av in $antivirusStatus) {
        Add-ToLog -Message "`nService : $($av.Name)" -ForegroundColor Cyan
        
        if ($av.Present -eq $false) {
            Add-ToLog -Message "   [ALERTE] Aucune solution antivirus detectee sur ce serveur." -ForegroundColor Red
            Add-ToLog -Message "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.ServerAntivirusStatus.status = "FAIL"
            $auditResults.OSSecurity.ServerAntivirusStatus.comments += "No antivirus solution detected. "
            $auditResults.OSSecurity.ServerAntivirusStatus.recommendations += $av.Recommendation
            $hasIssue = $true
        } else {
            # Statut du service
            if ($av.ServiceRunning) {
                Add-ToLog -Message "   [OK] Le service antivirus est en cours d'execution." -ForegroundColor Green
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Antivirus service is running. "
            } else {
                Add-ToLog -Message "   [ALERTE] Le service antivirus n'est pas en cours d'execution." -ForegroundColor Red
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Antivirus service is not running. "
                $hasIssue = $true
            }

            # Monitoring en temps reel (pour Defender uniquement)
            if ($null -ne $av.RealtimeMonitoring) {
                if ($av.RealtimeMonitoring) {
                    Add-ToLog -Message "   [OK] La protection en temps reel est activee." -ForegroundColor Green
                    $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Real-time monitoring is enabled. "
                } else {
                    Add-ToLog -Message "   [ALERTE] La protection en temps reel est desactivee." -ForegroundColor Red
                    $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Real-time monitoring is disabled. "
                    $hasIssue = $true
                }
            }

            # Status global
            if ($av.OverallProtected) {
                Add-ToLog -Message "   [OK] Protection globale : Active" -ForegroundColor Green
            } else {
                Add-ToLog -Message "   [ALERTE] Protection globale : Inactive ou degradee" -ForegroundColor Red
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "Global protection is inactive or degraded. "
                $hasIssue = $true
            }

            # Contexte serveur
            if ($av.IsDomainController) {
                Add-ToLog -Message "   [INFO] Cette machine est un controleur de domaine." -ForegroundColor Magenta
                $auditResults.OSSecurity.ServerAntivirusStatus.comments += "This machine is a Domain Controller. "
            }

            # Description et recommandation
            Add-ToLog -Message "   Description : $($av.Description)" -ForegroundColor Gray
            Add-ToLog -Message "   Recommandation : $($av.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit de la configuration LM Hash :" -ForegroundColor Gray
try {
    $lmHashStatus = Get-LMHashStatus

    if ($lmHashStatus -and $lmHashStatus.Value) {
        $lm = $lmHashStatus.Value

        Add-ToLog -Message "   Path: $($lm.Path)" -ForegroundColor Gray
        Add-ToLog -Message "   NoLMHash Value: $($lm.NoLMHash)" -ForegroundColor Gray

        if ($lm.LMStored -eq $true) {
            Add-ToLog -Message "   [ALERTE] Les hachs LM peuvent etre stockes sur ce systeme." -ForegroundColor Red
            Add-ToLog -Message "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.LMHash.status = "FAIL"
            $auditResults.OSSecurity.LMHash.comments += "LM hashes may be stored on this system (NoLMHash != 1). "
        } else {
            Add-ToLog -Message "   [OK] Les hachs LM ne sont pas stockes (NoLMHash = 1)." -ForegroundColor Green
            Add-ToLog -Message "   Recommandation : $($lm.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.LMHash.status = "PASS"
            $auditResults.OSSecurity.LMHash.comments += "LM hashes are not stored (NoLMHash = 1). "
        }
        $auditResults.OSSecurity.LMHash.recommendations += $lm.Recommendation

        # Affichage des actions proposees
        if ($lmHashStatus.Xml) {
            Add-ToLog -Message "`n   Action proposee :" -ForegroundColor Gray
            Add-ToLog -Message "      - $($lmHashStatus.Xml.Category) : $($lmHashStatus.Xml.Description)" -ForegroundColor Yellow
            Add-ToLog -Message "         Commande : $($lmHashStatus.Xml.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit de la protection LSASS :" -ForegroundColor Gray
try {
    $lsassAudit = Get-LsassProtectionStatus

    if ($lsassAudit -and $lsassAudit.Value) {
        $p = $lsassAudit.Value

        Add-ToLog -Message "   LSA Path : $($p.LsaPath)" -ForegroundColor Gray
        Add-ToLog -Message "   RunAsPPL : $($p.RunAsPPL)" -ForegroundColor Gray

        $lsassOk = $false
        switch ($p.RunAsPPL) {
            2 {
                Add-ToLog -Message "   [OK] LSA protection activee (RunAsPPL = 2, Secure Boot requis)." -ForegroundColor Green
                $lsassOk = $true
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is enabled (RunAsPPL = 2, Secure Boot required). "
            }
            1 {
                Add-ToLog -Message "   [OK] LSA protection activee (RunAsPPL = 1)." -ForegroundColor Green
                $lsassOk = $true
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is enabled (RunAsPPL = 1). "
            }
            default {
                Add-ToLog -Message "   [ALERTE] LSA protection non activee ou valeur inconnue." -ForegroundColor Red
                $auditResults.OSSecurity.LSASSProtection.comments += "LSA protection is not enabled or unknown value. "
            }
        }

        Add-ToLog -Message "   WDigest Path : $($p.WDigestPath)" -ForegroundColor Gray
        Add-ToLog -Message "   UseLogonCredential : $($p.UseLogonCredential)" -ForegroundColor Gray

        if ($p.UseLogonCredential -eq 1) {
            Add-ToLog -Message "   [ALERTE] WDigest active — mots de passe potentiellement stockes en clair dans LSASS." -ForegroundColor Red
            $auditResults.OSSecurity.LSASSProtection.comments += "WDigest is enabled - passwords may be stored in LSASS. "
            $lsassOk = $false
        } else {
            Add-ToLog -Message "   [OK] WDigest desactive ou valeur explicite presente." -ForegroundColor Green
            $auditResults.OSSecurity.LSASSProtection.comments += "WDigest is disabled. "
        }

        Add-ToLog -Message "   Recommandation : $($p.Recommendation)" -ForegroundColor Yellow
        $auditResults.OSSecurity.LSASSProtection.recommendations += $p.Recommendation

        if ($lsassAudit.Xml) {
            Add-ToLog -Message "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $lsassAudit.Xml) {
                Add-ToLog -Message "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Add-ToLog -Message "         Commande : $($item.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit Credential Guard :" -ForegroundColor Gray
try {
    $cg = Get-CredentialGuardStatus

    if ($cg) {
        Add-ToLog -Message "   LsaPath        : $($cg.LsaPath)" -ForegroundColor Gray
        Add-ToLog -Message "   LsaCfgFlags    : $($cg.LsaCfgFlags)" -ForegroundColor Gray
        Add-ToLog -Message "   Status         : $($cg.CredentialGuard)" -ForegroundColor Gray

        $cgEnabled = $false
        if ($cg.LsaCfgFlags -eq 1 -or $cg.LsaCfgFlags -eq 2) {
            Add-ToLog -Message "   [OK] Credential Guard active." -ForegroundColor Green
            $cgEnabled = $true
            $auditResults.OSSecurity.CredentialGuard.comments += "Credential Guard is enabled (LsaCfgFlags = $($cg.LsaCfgFlags)). "
        } else {
            Add-ToLog -Message "   [ALERTE] Credential Guard desactive ou non configure." -ForegroundColor Red
            $auditResults.OSSecurity.CredentialGuard.comments += "Credential Guard is disabled or not configured (LsaCfgFlags = $($cg.LsaCfgFlags)). "
        }

        Add-ToLog -Message "   TPM present    : $($cg.HasTPM)" -ForegroundColor Gray
        Add-ToLog -Message "   SecureBoot     : $($cg.SecureBoot)" -ForegroundColor Gray
        Add-ToLog -Message "   Virtualisation : $($cg.Virtualization)" -ForegroundColor Gray

        if (-not $cg.HasTPM -or -not $cg.SecureBoot -or -not $cg.Virtualization) {
            Add-ToLog -Message "`n   [PREREQUIS MANQUANTS]" -ForegroundColor Yellow
            if (-not $cg.HasTPM)    { Add-ToLog -Message "      - TPM manquant ou version non supportee." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "TPM not available. " }
            if (-not $cg.SecureBoot){ Add-ToLog -Message "      - Secure Boot non active." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "Secure Boot not enabled. " }
            if (-not $cg.Virtualization) { Add-ToLog -Message "      - Virtualisation materielle non presente." -ForegroundColor Yellow; $auditResults.OSSecurity.CredentialGuard.comments += "Virtualization not available. " }
            $auditResults.OSSecurity.CredentialGuard.status = "WARNING"
        } else {
            $auditResults.OSSecurity.CredentialGuard.status = if ($cgEnabled) { "PASS" } else { "FAIL" }
        }
        
        Add-ToLog -Message "`n   Recommandations : $($cg.Recommendations)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit Device Guard / VBS :" -ForegroundColor Gray
try {
    $dg = Get-DeviceGuardStatus

    if ($dg) {
        Add-ToLog -Message "   VBS actif         : $($dg.VBS_Active)" -ForegroundColor Gray
        Add-ToLog -Message "   WDAC actif        : $($dg.WDAC_Active)" -ForegroundColor Gray
        Add-ToLog -Message "   CI Enforcement    : $($dg.CodeIntegrityPolicyEnforcementStatus)" -ForegroundColor Gray
        Add-ToLog -Message "   SecurityServicesConfigured : $($dg.SecurityServicesConfigured)" -ForegroundColor Gray
        Add-ToLog -Message "   SecurityServicesRunning    : $($dg.SecurityServicesRunning)" -ForegroundColor Gray
        Add-ToLog -Message "   Commentaire       : $($dg.Comment)" -ForegroundColor Gray

        if ($dg.VBS_Active -or $dg.WDAC_Active) {
            Add-ToLog -Message "   [OK] Virtualization-Based Security (VBS) et/ou WDAC detecte(s)." -ForegroundColor Green

            $auditResults.OSSecurity.DeviceGuard_VBS.status = "PASS"
            $auditResults.OSSecurity.DeviceGuard_VBS.comments += "VBS and/or WDAC is active. "

            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Audit') {
                Add-ToLog -Message "   [INFO] WDAC en mode Audit — examiner les journaux et prevoir passage en Enforced si stable." -ForegroundColor Yellow
                $auditResults.OSSecurity.DeviceGuard_VBS.comments += "WDAC is in Audit mode. "
                $auditResults.OSSecurity.DeviceGuard_VBS.status = "WARNING"
            }
            if ($dg.WDAC_Active -and $dg.CodeIntegrityPolicyEnforcementStatus -match 'Enforced') {
                Add-ToLog -Message "   [OK] WDAC / Code Integrity en mode Enforced." -ForegroundColor Green
                $auditResults.OSSecurity.DeviceGuard_VBS.comments += "WDAC is in Enforced mode. "
            }
        }
        else {
            Add-ToLog -Message "   [ALERTE] Ni VBS ni WDAC actives sur ce systeme." -ForegroundColor Red
            $auditResults.OSSecurity.DeviceGuard_VBS.status = "FAIL"
            $auditResults.OSSecurity.DeviceGuard_VBS.comments += "Neither VBS nor WDAC is active. "
        }
        
        Add-ToLog -Message "   Recommandation : $($dg.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit Exploit Protection (Process Mitigations) :" -ForegroundColor Gray
try {
    $epAudit = Get-ExploitProtectionStatus

    if ($epAudit -and $epAudit.Value) {
        $ep = $epAudit.Value
        $issues = @()

        Add-ToLog -Message "   DEP (Data Execution Prevention)            : $($ep.DEP_Enable)" -ForegroundColor Gray
        if (-not $ep.DEP_Enable) { $issues += 'DEP' ; Add-ToLog -Message "      [ALERTE] DEP non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] DEP active." -ForegroundColor Green }

        Add-ToLog -Message "   CFG (Control Flow Guard)                   : $($ep.CFG_Enable)" -ForegroundColor Gray
        if (-not $ep.CFG_Enable) { $issues += 'CFG' ; Add-ToLog -Message "      [ALERTE] CFG non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] CFG active." -ForegroundColor Green }

        Add-ToLog -Message "   SEHOP (SEH Overwrite Protection)          : $($ep.SEHOP_Enable)" -ForegroundColor Gray
        if (-not $ep.SEHOP_Enable) { $issues += 'SEHOP' ; Add-ToLog -Message "      [ALERTE] SEHOP non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] SEHOP active." -ForegroundColor Green }

        Add-ToLog -Message "   ASLR Bottom-Up                              : $($ep.ASLR_BottomUP)" -ForegroundColor Gray
        if (-not $ep.ASLR_BottomUP) { $issues += 'ASLR_BottomUP' ; Add-ToLog -Message "      [ALERTE] ASLR Bottom-Up non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] ASLR Bottom-Up active." -ForegroundColor Green }

        Add-ToLog -Message "   ASLR High-Entropy                           : $($ep.ASLR_HighEntropy)" -ForegroundColor Gray
        if (-not $ep.ASLR_HighEntropy) { $issues += 'ASLR_HighEntropy' ; Add-ToLog -Message "      [ALERTE] ASLR High-Entropy non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] ASLR High-Entropy active." -ForegroundColor Green }

        Add-ToLog -Message "   ASLR ForceRelocateImages                    : $($ep.ASLR_ForceRelocateImages)" -ForegroundColor Gray
        if (-not $ep.ASLR_ForceRelocateImages) { $issues += 'ASLR_ForceRelocateImages' ; Add-ToLog -Message "      [ALERTE] ForceRelocateImages non active." -ForegroundColor Red } else { Add-ToLog -Message "      [OK] ForceRelocateImages active." -ForegroundColor Green }

        Add-ToLog -Message "`n   Synthese :" -ForegroundColor Gray
        if (($issues | Measure-Object).Count -eq 0) {
            Add-ToLog -Message "      [OK] Parametres globaux d'Exploit Protection solides." -ForegroundColor Green
            Add-ToLog -Message "      Recommandation : $($ep.Recommendation)" -ForegroundColor Gray
            $auditResults.OSSecurity.ExploitProtection.status = "PASS"
            $auditResults.OSSecurity.ExploitProtection.comments += "Exploit Protection settings are strong. "
        } else {
            Add-ToLog -Message "      [ALERTE] Parametres manquants ou desactives : $($issues -join ', ')" -ForegroundColor Red
            Add-ToLog -Message "      Recommandation : $($ep.Recommendation)" -ForegroundColor Yellow
            $auditResults.OSSecurity.ExploitProtection.status = "FAIL"
            $auditResults.OSSecurity.ExploitProtection.comments += "Missing or disabled settings: $($issues -join ', '). "
        }
        
        $auditResults.OSSecurity.ExploitProtection.recommendations += $ep.Recommendation

        if ($epAudit.Xml) {
            Add-ToLog -Message "`n   Actions proposees :" -ForegroundColor Gray
            foreach ($item in $epAudit.Xml) {
                Add-ToLog -Message "      - $($item.Category) : $($item.Description)" -ForegroundColor Yellow
                Add-ToLog -Message "         Commande : $($item.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit Attack Surface Reduction (ASR) :" -ForegroundColor Gray
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

            Add-ToLog -Message "`n   RuleId : $($rule.RuleId)  $label" -ForegroundColor Cyan
            Add-ToLog -Message "      Mode : $status" -ForegroundColor $color
            Add-ToLog -Message "      Commentaire : $($rule.Comment)" -ForegroundColor Gray
            if ($rule.Recommendation) { 
                Add-ToLog -Message "      Recommandation : $($rule.Recommendation)" -ForegroundColor Yellow
                $auditResults.OSSecurity.ASR.recommendations += $rule.Recommendation
            }
            $auditResults.OSSecurity.ASR.comments += "Rule $($rule.RuleId) is $status. "
        }
        $auditResults.OSSecurity.ASR.status = if ($hasBlockedRules) { "PASS" } else { "WARNING" }
    }
    else {
        # Cas ou Get-ASRStatus renvoie un objet unique indiquant l'absence de regles
        Add-ToLog -Message "   $($asrAudit.Comment)" -ForegroundColor Red
        Add-ToLog -Message "   Recommandation : $($asrAudit.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit Network Protection (Microsoft Defender) :" -ForegroundColor Gray
try {
    $np = Get-NetworkProtectionStatus

    if ($np) {
        Add-ToLog -Message "   Mode detecte : $($np.Mode)" -ForegroundColor Gray
        switch ($np.Mode) {
            'Block' {
                Add-ToLog -Message "   [OK] Network Protection en mode Block." -ForegroundColor Green
                $auditResults.OSSecurity.NetworkProtection.status = "PASS"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is in Block mode. "
            }
            'Audit' {
                Add-ToLog -Message "   [INFO] Network Protection en mode Audit." -ForegroundColor Yellow
                $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is in Audit mode. "
            }
            'Off' {
                Add-ToLog -Message "   [ALERTE] Network Protection desactive." -ForegroundColor Red
                $auditResults.OSSecurity.NetworkProtection.status = "FAIL"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is disabled. "
            }
            'NotConfigured' {
                Add-ToLog -Message "   [ALERTE] Network Protection non configure." -ForegroundColor Red
                $auditResults.OSSecurity.NetworkProtection.status = "FAIL"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection is not configured. "
            }
            default {
                Add-ToLog -Message "   [INCONNU] Valeur brute : $($np.RawValue)" -ForegroundColor Yellow
                $auditResults.OSSecurity.NetworkProtection.status = "WARNING"
                $auditResults.OSSecurity.NetworkProtection.comments += "Network Protection has unknown status: $($np.RawValue). "
            }
        }

        Add-ToLog -Message "   EnableNetworkProtection : $($np.EnableNetworkProtection)" -ForegroundColor Gray
        Add-ToLog -Message "`n   Recommandation : $($np.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit Controlled Folder Access (Defender) :" -ForegroundColor Gray
try {
    $cfa = Get-ControlledFolderAccessStatus

    if ($cfa) {
        Add-ToLog -Message "   Mode detecte : $($cfa.Mode)" -ForegroundColor Gray

        switch ($cfa.Mode) {
            'Block' {
                Add-ToLog -Message "   [OK] Controlled Folder Access en mode Block." -ForegroundColor Green
                $auditResults.OSSecurity.ControlledFolderAccess.status = "PASS"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Block mode. "
            }
            'Audit' {
                Add-ToLog -Message "   [INFO] Controlled Folder Access en mode Audit." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Audit mode. "
            }
            'Block disk modification only' {
                Add-ToLog -Message "   [INFO] CFA en mode 'Block disk modification only'." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Block disk modification only mode. "
            }
            'Audit disk modification only' {
                Add-ToLog -Message "   [INFO] CFA en mode 'Audit disk modification only'." -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is in Audit disk modification only mode. "
            }
            'Off' {
                Add-ToLog -Message "   [ALERTE] Controlled Folder Access desactive." -ForegroundColor Red
                $auditResults.OSSecurity.ControlledFolderAccess.status = "FAIL"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is disabled. "
            }
            'NotConfigured' {
                Add-ToLog -Message "   [ALERTE] Controlled Folder Access non configure." -ForegroundColor Red
                $auditResults.OSSecurity.ControlledFolderAccess.status = "FAIL"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access is not configured. "
            }
            default {
                Add-ToLog -Message "   [INCONNU] Valeur brute : $($cfa.EnableControlledFolderAccess)" -ForegroundColor Yellow
                $auditResults.OSSecurity.ControlledFolderAccess.status = "WARNING"
                $auditResults.OSSecurity.ControlledFolderAccess.comments += "Controlled Folder Access has unknown status: $($cfa.EnableControlledFolderAccess). "
            }
        }

        Add-ToLog -Message "`n   Recommandation : $($cfa.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit Smart App Control :" -ForegroundColor Gray
try {
    $sac = Get-SmartAppControlStatus

    if ($sac) {
        Add-ToLog -Message "   Smart App Control : $($sac.SmartApp_State)" -ForegroundColor Gray

        switch ($sac.SmartApp_State) {
            'On' {
                Add-ToLog -Message "   [OK] Smart App Control active." -ForegroundColor Green
                $auditResults.OSSecurity.SmartAppControl.status = "PASS"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is enabled. "
            }
            'Evaluation' {
                Add-ToLog -Message "   [INFO] Smart App Control en mode Evaluation." -ForegroundColor Yellow
                $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is in Evaluation mode. "
            }
            'Off' {
                Add-ToLog -Message "   [ALERTE] Smart App Control desactive." -ForegroundColor Red
                $auditResults.OSSecurity.SmartAppControl.status = "FAIL"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is disabled. "
            }
            'NotConfigured' {
                Add-ToLog -Message "   [ALERTE] Smart App Control non configure." -ForegroundColor Red
                $auditResults.OSSecurity.SmartAppControl.status = "FAIL"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control is not configured. "
            }
            default {
                Add-ToLog -Message "   [INCONNU] Valeur detectee : $($sac.SmartApp_State)" -ForegroundColor Yellow
                $auditResults.OSSecurity.SmartAppControl.status = "WARNING"
                $auditResults.OSSecurity.SmartAppControl.comments += "Smart App Control has unknown state: $($sac.SmartApp_State). "
            }
        }
        Add-ToLog -Message "`n   Recommandation : Tester en mode Evaluation puis activer (On) sur systemes compatibles." -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit du mode langage PowerShell :" -ForegroundColor Gray
try {
    $psMode = Get-PowerShellLanguageMode

    if ($psMode) {
        Add-ToLog -Message "   LanguageMode : $($psMode.LanguageMode)" -ForegroundColor Gray

        if ($psMode.IsConstrained) {
            Add-ToLog -Message "   [OK] PowerShell en ConstrainedLanguage." -ForegroundColor Green
            $auditResults.OSSecurity.PowershellLanguageMode.status = "PASS"
            $auditResults.OSSecurity.PowershellLanguageMode.comments += "PowerShell is in ConstrainedLanguage mode. "
        }
        else {
            Add-ToLog -Message "   [ALERTE] PowerShell en FullLanguage (ou moins restreint)." -ForegroundColor Red
            $auditResults.OSSecurity.PowershellLanguageMode.status = "FAIL"
            $auditResults.OSSecurity.PowershellLanguageMode.comments += "PowerShell is in FullLanguage or less restricted mode: $($psMode.LanguageMode). "
        }
        Add-ToLog -Message "   Recommandation : $($psMode.Recommendation)" -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit AutoRun (NoDriveTypeAutorun) :" -ForegroundColor Gray
try {
    $ar = Get-AutorunStatus

    if ($ar -and $ar.Value) {
        $hasIssue = $false
        $arRecs = @()
        foreach ($entry in $ar.Value) {
            Add-ToLog -Message "`n   Scope : $($entry.Scope)" -ForegroundColor Cyan
            Add-ToLog -Message "      Valeur brute : $($entry.Value)" -ForegroundColor Gray
            Add-ToLog -Message "      Commentaire  : $($entry.Comment)" -ForegroundColor Gray

            if ($entry.AutoRunEnabled -eq $true) {
                Add-ToLog -Message "      [ALERTE] Autorun potentiellement active." -ForegroundColor Red
                Add-ToLog -Message "      Recommandation : $($entry.Recommendation)" -ForegroundColor Yellow
                $auditResults.DeviceSecurity.AutoRun.comments += "AutoRun is potentially enabled for scope $($entry.Scope). "
                $arRecs += $entry.Recommendation
                $hasIssue = $true
            }
            else {
                Add-ToLog -Message "      [OK] Autorun desactive pour ce scope." -ForegroundColor Green
                Add-ToLog -Message "      Recommandation : $($entry.Recommendation)" -ForegroundColor Gray
                $auditResults.DeviceSecurity.AutoRun.comments += "AutoRun is disabled for scope $($entry.Scope). "
                $arRecs += $entry.Recommendation
            }
        }

        if ($ar.Xml) {
            Add-ToLog -Message "`n   Actions proposees :" -ForegroundColor Gray
            Add-ToLog -Message "      - $($ar.Xml.Category) : $($ar.Xml.Description)" -ForegroundColor Yellow
            Add-ToLog -Message "         Commande : $($ar.Xml.Command)" -ForegroundColor DarkGray
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

Add-ToLog -Message "`n[+] Audit BitLocker :" -ForegroundColor Gray
try {

    if ($context.HardwareType -ne 'Virtual Machine') {
        
        $bitlocker = Get-BitLockerAudit

        if ($bitlocker) {
            $allEncrypted = $true
            $blRecs = @()
            foreach ($vol in $bitlocker) {
                Add-ToLog -Message "`n   Volume : $($vol.MountPoint) ($($vol.VolumeType))" -ForegroundColor Cyan
                Add-ToLog -Message "      ProtectionStatus   : $($vol.ProtectionStatus)  |  Chiffrement : $($vol.EncryptionPercent)% " -ForegroundColor Gray
                if ($vol.ProtectionStatus -eq 'On' -and $vol.EncryptionPercent -ge 100) {
                    Add-ToLog -Message "      [OK] Volume chiffre et protege." -ForegroundColor Green
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) is encrypted and protected. "
                }
                elseif ($vol.ProtectionStatus -eq 'Suspended') {
                    Add-ToLog -Message "      [INFO] Protection suspendue." -ForegroundColor Yellow
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) has suspended protection. "
                    $allEncrypted = $false
                }
                else {
                    Add-ToLog -Message "      [ALERTE] Volume non protege ou chiffrement incomplet." -ForegroundColor Red
                    $auditResults.DeviceSecurity.BitLocker.comments += "Volume $($vol.MountPoint) is not protected or encryption is incomplete. "
                    $allEncrypted = $false
                }

                Add-ToLog -Message "      TPM : $($vol.HasTPM)    PIN : $($vol.HasPIN)    RecoveryKey : $($vol.HasRecoveryPassword)" -ForegroundColor Gray
                Add-ToLog -Message "      Commentaire : $($vol.Comment)" -ForegroundColor Gray
                Add-ToLog -Message "      Recommandation : $($vol.Recommendation)" -ForegroundColor Yellow
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
        Add-ToLog -Message "   [INFO] Systeme virtuel detecte — saut de l'audit BitLocker." -ForegroundColor Yellow
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

Add-ToLog -Message "`n[+] Audit indicateurs de chiffrement tiers :" -ForegroundColor Gray
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
            Add-ToLog -Message "`n   Solution : $name" -ForegroundColor Cyan
            Add-ToLog -Message "      Present : $present" -ForegroundColor Gray

            if ($present) {
                Add-ToLog -Message "      [INFO] Chiffrement tiers detecte : $name" -ForegroundColor Green
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Third-party encryption detected: $name. "
                if ($item.Version) { 
                    Add-ToLog -Message "      Version : $($item.Version)" -ForegroundColor Gray
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Version: $($item.Version). "
                }
                if ($item.Details) { 
                    Add-ToLog -Message "      Details : $($item.Details)" -ForegroundColor Gray
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Details: $($item.Details). "
                }
                if ($item.Recommendation) { 
                    Add-ToLog -Message "      Recommandation : $($item.Recommendation)" -ForegroundColor Yellow
                    $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.recommendations += $item.Recommendation
                }
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
            } else {
                Add-ToLog -Message "      [OK] Aucun chiffrement tiers detecte pour cet item." -ForegroundColor Green
            }
        }
    }
    else {
        # Cas objet unique attendu avec proprietes HasThirdParty/Detected/Details/Recommendation
        $has = $tpe.HasThirdParty  -or $tpe.Detected -or $false
        Add-ToLog -Message "   Indicateur chiffrement tiers detecte : $has" -ForegroundColor Gray
        if ($has) {
            Add-ToLog -Message "   [INFO] Un chiffrement tiers semble present. Details : $($tpe.Details)" -ForegroundColor Green
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.status = "PASS"
            $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.comments += "Third-party encryption detected. Details: $($tpe.Details). "
            if ($tpe.Recommendation) { 
                Add-ToLog -Message "   Recommandation : $($tpe.Recommendation)" -ForegroundColor Yellow
                $auditResults.DeviceSecurity.ThirdPartyEncryptionIndicators.recommendations += $tpe.Recommendation
            }
        } else {
            Add-ToLog -Message "   [OK] Aucun chiffrement tiers detecte." -ForegroundColor Magenta
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

Add-ToLog -Message "`n[+] Audit du dernier redemarrage :" -ForegroundColor Gray
try {
    $lr = Get-LastReboot

    if ($lr) {
        Add-ToLog -Message "   Role de la machine : $($lr.ComputerRole)" -ForegroundColor Gray
        Add-ToLog -Message "   Dernier demarrage   : $($lr.LastBootTime)" -ForegroundColor Gray
        Add-ToLog -Message "   Uptime              : $($lr.Uptime) (jours: $($lr.UptimeDays))" -ForegroundColor Gray
        Add-ToLog -Message "   Seuil recommande    : $($lr.ThresholdDays) jours" -ForegroundColor Gray

        $auditResults.UpdateManagement.LastReboot_Uptime.comments += "Last boot time: $($lr.LastBootTime). Uptime: $($lr.UptimeDays) days. "

        if ($lr.UptimeDays -gt $lr.ThresholdDays) {
            Add-ToLog -Message "   [ALERTE] Uptime superieur au seuil ($($lr.ThresholdDays) jours)." -ForegroundColor Red
            Add-ToLog -Message "   Recommandation : $($lr.Recommendation)" -ForegroundColor Yellow
            $auditResults.UpdateManagement.LastReboot_Uptime.status = "FAIL"
        }
        else {
            Add-ToLog -Message "   [OK] Uptime dans la plage attendue." -ForegroundColor Green
            Add-ToLog -Message "   Recommandation : $($lr.Recommendation)" -ForegroundColor Gray
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

Add-ToLog -Message "`n[+] Audit des journaux et de la collecte d'evenements :" -ForegroundColor Gray
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
            Add-ToLog -Message "`n   Log : $($l.LogName)" -ForegroundColor Cyan
            if (-not $l.IsEnabled) {
                Add-ToLog -Message "      [ALERTE] Desactive ou indisponible." -ForegroundColor Red
                Add-ToLog -Message "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) is disabled. "
                $logRecs += $l.Recommendation
                $logIssue = $true
                continue
            }

            Add-ToLog -Message "      Enregistres : $($l.RecordCount)  |  MaxSize : $($l.MaximumSizeMB) MB  |  Reco : $($l.RecoSizeMB) MB" -ForegroundColor Gray

            if ($l.IsSizeOK -eq $true) {
                Add-ToLog -Message "      [OK] Taille du journal conforme." -ForegroundColor Green
                Add-ToLog -Message "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) size is compliant. "
                $logRecs += $l.Recommendation
            }
            elseif ($l.IsSizeOK -eq $false) {
                Add-ToLog -Message "      [ALERTE] Taille du journal insuffisante." -ForegroundColor Red
                Add-ToLog -Message "      Recommendation : $($l.Recommendation)" -ForegroundColor Yellow
                $auditResults.Logging.LogStatus.comments += "Log $($l.LogName) size is insufficient. "
                $logRecs += $l.Recommendation
                $logIssue = $true
            }
            else {
                Add-ToLog -Message "      [INFO] Aucune recommandation de taille definie." -ForegroundColor Yellow
                Add-ToLog -Message "      Recommendation : $($l.Recommendation)" -ForegroundColor Gray
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
            Add-ToLog -Message "`n   Source : $($e.Name)" -ForegroundColor Cyan
            Add-ToLog -Message "      Active : $($e.IsEnabled)" -ForegroundColor Gray
            Add-ToLog -Message "      Commentaire : $($e.Comment)" -ForegroundColor Gray
            Add-ToLog -Message "      Recommendation : $($e.Recommendation)" -ForegroundColor Yellow
            
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
        Add-ToLog -Message "`n   Agents de collecte detectes :" -ForegroundColor Gray
        $agentFound = $false
        $laRecs = @()
        foreach ($a in $agents) {
            if ($a.IsLogAgent) {
                Add-ToLog -Message "      - $($a.DisplayName) (version: $($a.DisplayVersion))" -ForegroundColor Green
                Add-ToLog -Message "         Recommendation : $($a.Recommendation)" -ForegroundColor Gray
                $auditResults.Logging.LogAgentStatus.comments += "Log agent detected: $($a.DisplayName) (version: $($a.DisplayVersion)). "
                $laRecs += $a.Recommendation
                $agentFound = $true
            } else {
                Add-ToLog -Message "      - Aucun agent connu detecte sur l'entree (bruit possible)." -ForegroundColor Yellow
                Add-ToLog -Message "         Commentaire : $($a.Comment)" -ForegroundColor Gray
                $auditResults.Logging.LogAgentStatus.comments += "Unknown entry detected: $($a.Comment). "
            }
        }
        $auditResults.Logging.LogAgentStatus.status = if ($agentFound) { "PASS" } else { "FAIL" }
        if ($laRecs.Count -gt 0) {
            $auditResults.Logging.LogAgentStatus.recommendations = ($laRecs | Select-Object -Unique) -join " | "
        }
    } else {
        Add-ToLog -Message "`n   [ALERTE] Aucun agent de collecte/SIEM detecte." -ForegroundColor Red
        Add-ToLog -Message "      Recommendation : Installer/configurer un agent pour centraliser les logs." -ForegroundColor Yellow
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
        Add-ToLog -Message "[✓] Actions de remediation exportees : $xmlPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Erreur lors de l'export des actions XML : $($_.Exception.Message)"
    }
}

# --- Fin ---
Add-ToLog -Message "`nAudit termine." -ForegroundColor Cyan
