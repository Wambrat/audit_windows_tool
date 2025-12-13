<#
.SYNOPSIS
    Audite la configuration LAPS (Windows LAPS et Legacy LAPS).

.DESCRIPTION
    Vérifie la présence des clés de registre pour les différentes méthodes de déploiement LAPS :
    - Windows LAPS (GPO, CSP, Local)
    - Legacy LAPS (AdmPwd - Obsolète)

.OUTPUTS
    PSCustomObject
#>
function Get-LAPSAudit {
    [CmdletBinding()]
    param()

    process {
        # Définition des cibles à vérifier
        $lapsTargets = @(
            @{ Name = "Windows LAPS (CSP)";   Path = "HKLM:\Software\Microsoft\Policies\LAPS"; Type = "Modern" },
            @{ Name = "Windows LAPS (GPO)";   Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"; Type = "Modern" },
            @{ Name = "Legacy LAPS (AdmPwd)"; Path = "HKLM:\Software\Policies\Microsoft Services\AdmPwd"; Type = "Legacy" }
        )

        # Variables pour accumuler les résultats
        $detectedConfigs = @()
        $hasLegacy = $false
        $hasModern = $false
        
        # --- 1. Scan des clés ---
        foreach ($target in $lapsTargets) {
            if (Test-Path -Path $target.Path) {
                # On récupère quelques infos intéressantes si possible (ex: Complexité)
                $props = Get-ItemProperty -Path $target.Path -ErrorAction SilentlyContinue
                
                $configDetails = [PSCustomObject]@{
                    Method = $target.Name
                    Path   = $target.Path
                    Type   = $target.Type
                    # Exemple de récupération de valeur (dépend de la version)
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
            $recommandation = "`nCONFORME : Windows LAPS (version moderne) est configuré."
            
            if ($hasLegacy) {
                $status = "WARNING"
                $recommandation += "`rATTENTION : Une configuration Legacy LAPS a aussi été détectée. Assurez-vous d'avoir terminé la migration et nettoyez les anciennes clés."
            }
        }
        elseif ($hasLegacy) {
            $status = "WARNING"
            $recommandation = "`nOBSOLÈTE : La version 'Legacy LAPS' est détectée. Microsoft recommande de migrer vers le nouveau 'Windows LAPS' (intégré à l'OS) qui supporte le chiffrement des mots de passe, l'historique et Azure AD."
        }
        else {
            $status = "FAIL"
            $recommandation = "`nAucune configuration LAPS (ni Legacy, ni Moderne) n'a été trouvée. Les mots de passe administrateurs locaux risquent d'être identiques ou statiques."
        }

        # --- 3. Sortie Objet ---
        return [PSCustomObject]@{
            Check           = "LAPS Configuration"
            Status          = $status
            DetectedMethods = if ($detectedConfigs) { ($detectedConfigs.Method -join ", ") } else { "None" }
            IsModern        = $hasModern
            IsLegacy        = $hasLegacy
            Recommendation  = $recommandation
            Details         = $detectedConfigs # Contient le détail des chemins trouvés
            Timestamp       = (Get-Date)
        }
    }
}