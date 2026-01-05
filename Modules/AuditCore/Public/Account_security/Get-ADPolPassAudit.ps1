# -----------------------------------------------------------------------------
# Fonction : Get-AuditPasswordPolicies
# Description : Audite les politiques de mots de passe.
#               1. Verifie si joint au domaine (sinon stop).
#               2. Si DC : Audit complet (Default + FGPP).
#               3. Si Non-DC : Best effort (AD distant si possible, sinon local).
#               Verifie la conformite ANSSI.
# -----------------------------------------------------------------------------

function Get-AuditPasswordPolicies {
    [CmdletBinding()]
    param()

    # --- DeFINITION DES STANDARDS ANSSI ---
    $AnssiSpecs = @{
        Standard   = @{ MinLen = 12; Complexity = $true; Rotation = $false; Lockout = $true }
        Privileged = @{ MinLen = 15; Complexity = $true; Rotation = $true;  Lockout = $true }
        Service    = @{ MinLen = 32; Complexity = $true; Rotation = $true;  Lockout = $true }
    }

    # 1. Verification Appartenance Domaine & Role
    try {
        $sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domainRole = $sysInfo.DomainRole # 4 or 5 = DC
        $isDC = ($domainRole -eq 4 -or $domainRole -eq 5)
    }
    catch {
        Write-Warning "Impossible de determiner le statut de la machine via WMI."
        return $null
    }

    # Initialisation des resultats pour machine domaine
    $results = @{
        MachineName = $env:COMPUTERNAME
        IsDomainController = $isDC
        StandardUserPolicy = $null
        PrivilegedAccountPolicy = @()
        ServiceAccountPolicy = @()
        ScanMethod = "Unknown"
        ComplianceChecks = @()
    }

    # Fonction locale pour verifier la conformite
    function Test-AnssiCompliance {
        param($PolicyObj, $Type, $Standard)
        
        $status = "CONFORME"
        $reasons = @()

        if (-not $PolicyObj) { return @{ Status = "N/A"; Reasons = @("Politique introuvable") } }

        # Verification Longueur
        if ($PolicyObj.MinPasswordLength -lt $Standard.MinLen) {
            $status = "NON CONFORME"
            $reasons += "Longueur min $($PolicyObj.MinPasswordLength) < $($Standard.MinLen)"
        }

        # Verification Complexite
        if ($Standard.Complexity -and (-not $PolicyObj.PasswordComplexityEnabled)) {
            $status = "NON CONFORME"
            $reasons += "Complexite desactivee"
        }

        # Verification Rotation (MaxAge)
        if ($Standard.Rotation) {
            if ($PolicyObj.MaxPasswordAge -eq [TimeSpan]::Zero -or $PolicyObj.MaxPasswordAge -eq [TimeSpan]::MaxValue) {
                $status = "NON CONFORME"
                $reasons += "Pas de rotation forcee"
            }
        }

        # Verification Verrouillage
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
    # COLLECTE DES DONNeES (Pour machines domaine)
    # -------------------------------------------------------------------------
    
    # --- CAS 1 : Non-DC (Best Effort) ---
    if (-not $isDC) {
        Write-Host "[INFO] Machine membre (non-DC). Tentative de lecture 'Best Effort'..." -ForegroundColor Cyan
        
        # Essai lecture AD Distant (necessite RSAT + Droits lecture)
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "[INFO] Module AD detecte. Tentative de lecture complete (Standard + FGPP)..." -ForegroundColor Green
                
                # Recuperation de tout ce qu'on peut (comme demande)
                $results.StandardUserPolicy = Get-ADDefaultDomainPasswordPolicy -Current LocalComputer -ErrorAction Stop
                
                $allPSOs = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
                if ($allPSOs) {
                    $results.PrivilegedAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Admin|Priv|Root|Tier" })
                    $results.ServiceAccountPolicy = @($allPSOs | Where-Object { $_.Name -match "Service|Svc|App" })
                }
                $results.ScanMethod = "Remote AD Query (RSAT)"
            }
            catch {
                Write-Warning "Module AD present mais acces distant impossible. Fallback local."
            }
        }
    }
    
    # --- CAS 2 : Controleur de Domaine (Audit Complet) ---
    else {
        Write-Host "[INFO] Controleur de Domaine detecte. Audit complet Active Directory." -ForegroundColor Magenta
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
            Write-Error "Erreur critique acces AD : $_"
        }
    }

    # -------------------------------------------------------------------------
    # ANALYSE DE CONFORMITe (Uniquement si objet AD recupere)
    # -------------------------------------------------------------------------
    
    # 1. Standard
    if ($results.StandardUserPolicy -isnot $null -and $results.StandardUserPolicy -isnot [array]) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $results.StandardUserPolicy -Type "Utilisateur Standard" -Standard $AnssiSpecs.Standard
    }

    # 2. Privilegies
    foreach ($p in $results.PrivilegedAccountPolicy) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $p -Type "Privilegie" -Standard $AnssiSpecs.Privileged
    }

    # 3. Services
    foreach ($p in $results.ServiceAccountPolicy) {
        $results.ComplianceChecks += Test-AnssiCompliance -PolicyObj $p -Type "Service/Haut-Priv" -Standard $AnssiSpecs.Service
    }

    return [PSCustomObject]$results
}
