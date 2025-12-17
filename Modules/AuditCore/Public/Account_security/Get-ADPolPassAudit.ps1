# -----------------------------------------------------------------------------
# Fonction : Get-AuditPasswordPolicies
# Description : Audite les politiques de mots de passe.
#               1. Vérifie si joint au domaine (sinon stop).
#               2. Si DC : Audit complet (Default + FGPP).
#               3. Si Non-DC : Best effort (AD distant si possible, sinon local).
#               Vérifie la conformité ANSSI.
# -----------------------------------------------------------------------------

function Get-AuditPasswordPolicies {
    [CmdletBinding()]
    param()

    # --- DÉFINITION DES STANDARDS ANSSI ---
    $AnssiSpecs = @{
        Standard   = @{ MinLen = 12; Complexity = $true; Rotation = $false; Lockout = $true }
        Privileged = @{ MinLen = 15; Complexity = $true; Rotation = $true;  Lockout = $true }
        Service    = @{ MinLen = 32; Complexity = $true; Rotation = $true;  Lockout = $true }
    }

    # 1. Vérification Appartenance Domaine & Rôle
    try {
        $sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domainRole = $sysInfo.DomainRole # 4 or 5 = DC
        $isDC = ($domainRole -eq 4 -or $domainRole -eq 5)
    }
    catch {
        Write-Warning "Impossible de déterminer le statut de la machine via WMI."
        return $null
    }

    # Initialisation des résultats pour machine domaine
    $results = @{
        MachineName = $env:COMPUTERNAME
        IsDomainController = $isDC
        StandardUserPolicy = $null
        PrivilegedAccountPolicy = @()
        ServiceAccountPolicy = @()
        ScanMethod = "Unknown"
        ComplianceChecks = @()
    }

    # Fonction locale pour vérifier la conformité
    function Test-AnssiCompliance {
        param($PolicyObj, $Type, $Standard)
        
        $status = "CONFORME"
        $reasons = @()

        if (-not $PolicyObj) { return @{ Status = "N/A"; Reasons = @("Politique introuvable") } }

        # Vérification Longueur
        if ($PolicyObj.MinPasswordLength -lt $Standard.MinLen) {
            $status = "NON CONFORME"
            $reasons += "Longueur min $($PolicyObj.MinPasswordLength) < $($Standard.MinLen)"
        }

        # Vérification Complexité
        if ($Standard.Complexity -and (-not $PolicyObj.PasswordComplexityEnabled)) {
            $status = "NON CONFORME"
            $reasons += "Complexité désactivée"
        }

        # Vérification Rotation (MaxAge)
        if ($Standard.Rotation) {
            if ($PolicyObj.MaxPasswordAge -eq [TimeSpan]::Zero -or $PolicyObj.MaxPasswordAge -eq [TimeSpan]::MaxValue) {
                $status = "NON CONFORME"
                $reasons += "Pas de rotation forcée"
            }
        }

        # Vérification Verrouillage
        if ($Standard.Lockout) {
            if ($PolicyObj.LockoutThreshold -eq 0) {
                $status = "NON CONFORME"
                $reasons += "Pas de verrouillage compte"
            }
        }

        return @{
            Type = $Type
            Name = $PolicyObj.Name
            Status = $status
            Details = if ($reasons) { $reasons -join ", " } else { "Respecte les recommandations ANSSI" }
        }
    }

    # -------------------------------------------------------------------------
    # COLLECTE DES DONNÉES (Pour machines domaine)
    # -------------------------------------------------------------------------
    
    # --- CAS 1 : Non-DC (Best Effort) ---
    if (-not $isDC) {
        Write-Host "[INFO] Machine membre (non-DC). Tentative de lecture 'Best Effort'..." -ForegroundColor Cyan
        
        # Essai lecture AD Distant (nécessite RSAT + Droits lecture)
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "[INFO] Module AD détecté. Tentative de lecture complète (Standard + FGPP)..." -ForegroundColor Green
                
                # Récupération de tout ce qu'on peut (comme demandé)
                $results.StandardUserPolicy = Get-ADDefaultDomainPasswordPolicy -Current LocalComputer -ErrorAction Stop
                
                $allPSOs = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
                if ($allPSOs) {
                    $results.PrivilegedAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Admin|Priv|Root|Tier" })
                    $results.ServiceAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Service|Svc|App" })
                }
                $results.ScanMethod = "Remote AD Query (RSAT)"
            }
            catch {
                Write-Warning "Module AD présent mais accès distant impossible. Fallback local."
            }
        }
    }
    
    # --- CAS 2 : Contrôleur de Domaine (Audit Complet) ---
    else {
        Write-Host "[INFO] Contrôleur de Domaine détecté. Audit complet Active Directory." -ForegroundColor Magenta
        $results.ScanMethod = "Direct AD Database"
        
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $results.StandardUserPolicy = Get-ADDefaultDomainPasswordPolicy -Current LocalComputer
            
            $allPSOs = Get-ADFineGrainedPasswordPolicy -Filter *
            if ($allPSOs) {
                $results.PrivilegedAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Admin|Priv|T0" })
                $results.ServiceAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Service|Svc|GMSA" })
            }
        }
        catch {
            Write-Error "Erreur critique accès AD : $_"
        }
    }

    # -------------------------------------------------------------------------
    # ANALYSE DE CONFORMITÉ (Uniquement si objet AD récupéré)
    # -------------------------------------------------------------------------
    
    # 1. Standard
    if ($results.StandardUserPolicy -isnot $null -and $results.StandardUserPolicy -isnot [array]) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $results.StandardUserPolicy -Type "Utilisateur Standard" -Standard $AnssiSpecs.Standard
    }

    # 2. Privilégiés
    foreach ($p in $results.PrivilegedAccountPolicy) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $p -Type "Privilégié" -Standard $AnssiSpecs.Privileged
    }

    # 3. Services
    foreach ($p in $results.ServiceAccountPolicy) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $p -Type "Service/Haut-Priv" -Standard $AnssiSpecs.Service
    }

    return [PSCustomObject]$results
}