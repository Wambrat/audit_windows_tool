<#
.SYNOPSIS
    Audite la configuration LAPS (Windows LAPS et Legacy LAPS).

.DESCRIPTION
    Verifie la presence des cles de registre pour les differentes methodes de deploiement LAPS :
    - Windows LAPS (GPO, CSP, Local)
    - Legacy LAPS (AdmPwd - Obsolete)

.OUTPUTS
    PSCustomObject
#>
function Get-LAPSAudit {
    [CmdletBinding()]
    param()

    process {
        # Definition des cibles a verifier
        $lapsTargets = @(
            @{ Name = "Windows LAPS (CSP)";   Path = "HKLM:\Software\Microsoft\Policies\LAPS"; Type = "Modern" },
            @{ Name = "Windows LAPS (GPO)";   Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Type = "Modern" },
            @{ Name = "Legacy LAPS (AdmPwd)"; Path = "HKLM:\Software\Policies\Microsoft Services\AdmPwd"; Type = "Legacy" }
        )

        # Variables pour accumuler les resultats
        $detectedConfigs = @()
        $hasLegacy = $false
        $hasModern = $false
        
        # --- 1. Scan des cles ---
        foreach ($target in $lapsTargets) {
            if (Test-Path -Path $target.Path) {
                # On recupere quelques infos interessantes si possible (ex: Complexite)
                $props = Get-ItemProperty -Path $target.Path -ErrorAction SilentlyContinue
                
                $configDetails = [PSCustomObject]@{
                    Method = $target.Name
                    Path   = $target.Path
                    Type   = $target.Type
                    # Exemple de recuperation de valeur (depend de la version)
                    Complexity = if ($props.PasswordComplexity) { $props.PasswordComplexity } else { "Default/Not Set" }
                }
                
                $detectedConfigs += $configDetails

                if ($target.Type -eq "Legacy") { $hasLegacy = $true }
                if ($target.Type -eq "Modern") { $hasModern = $true }
            }
        }

        # --- 2. Analyse et Recommandations ---
        $status = "UNKNOWN"
        $recommandation = ""

        if ($hasModern) {
            $status = "PASS"
            $recommandation = "`nCONFORME : Windows LAPS (version moderne) est configure."
            
            if ($hasLegacy) {
                $status = "WARNING"
                $recommandation += "`rATTENTION : Une configuration Legacy LAPS a aussi ete detectee. Assurez-vous d'avoir termine la migration et nettoyez les anciennes cles."
            }
        }
        elseif ($hasLegacy) {
            $status = "WARNING"
            $recommandation = "`nOBSOLeTE : La version 'Legacy LAPS' est detectee. Microsoft recommande de migrer vers le nouveau 'Windows LAPS' (integre a l'OS) qui supporte le chiffrement des mots de passe, l'historique et Azure AD."
        }
        else {
            $status = "FAIL"
            $recommandation = "`nAucune configuration LAPS (ni Legacy, ni Moderne) n'a ete trouvee. Les mots de passe administrateurs locaux risquent d'etre identiques ou statiques."
        }

        # --- 3. Sortie Objet ---
        return [PSCustomObject]@{
            Check           = "LAPS Configuration"
            Status          = $status
            DetectedMethods = if ($detectedConfigs) { ($detectedConfigs.Method -join ", ") } else { "None" }
            IsModern        = $hasModern
            IsLegacy        = $hasLegacy
            Recommendation  = $recommandation
            Details         = $detectedConfigs # Contient le detail des chemins trouves
            Timestamp       = (Get-Date)
        }
    }
}
