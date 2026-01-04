<#
.SYNOPSIS
    Audite la politique de mot de passe locale et de verrouillage.

.DESCRIPTION
    Utilise l'outil natif 'secedit' pour exporter la configuration de sécurité actuelle
    et la compare aux recommandations de l'ANSSI via des switchs.
    - Longueur minimale (12 min, 15 recommandé pour admins).
    - Complexité (Activée).
    - Verrouillage compte (3 tentatives recommandées).

.OUTPUTS
    PSCustomObject
#>
function Get-PolPassAudit {
    [CmdletBinding()]
    param()

    process {
        $tempFile = "Modules\AuditCore\Public\Account_security\TEMP\security_dump.cfg"
        
        # Recommandations (Base de connaissances ANSSI)
        $Recos = @{
            MinLengthStandard = 12
            MinLengthAdmin    = 15
            LockoutThreshold  = 3
        }

        try {
            # 1. Export et Lecture
            #Start-Process -FilePath "secedit.exe" -ArgumentList "/export /cfg $tempFile /quiet" -Wait -WindowStyle Hidden
            SecEdit.exe /export /cfg $tempFile /quiet

            if (-not (Test-Path $tempFile)) { throw "Impossible de générer le fichier d'export SecEdit." }

            $content = Get-Content -Path $tempFile -Encoding Unicode -Raw

            # Parsing Regex (Inchangé)
            $null = $content -match "MinimumPasswordLength\s*=\s*(\d+)"
            $currentMinLength = if ($Matches[1]) { [int]$Matches[1] } else { 0 }

            $null = $content -match "PasswordComplexity\s*=\s*(\d+)"
            $currentComplexity = if ($Matches[1]) { [int]$Matches[1] } else { 0 }

            $null = $content -match "LockoutBadCount\s*=\s*(\d+)"
            $currentLockout = if ($Matches[1]) { [int]$Matches[1] } else { 0 }


            # 3. Analyse de Conformité avec SWITCH

            # --- Longueur ---
            # On switch sur $true pour évaluer les conditions mathématiques
            switch ($true) {
                ($currentMinLength -ge $Recos.MinLengthAdmin -and ($context.IsRunAsAdmin)) {
                    $statusLength = "EXCELLENT"
                    $msgLength = "Conforme Admin (15+ chars)."
                    break # On sort dès qu'on trouve, pour ne pas tester la suite
                }
                ($currentMinLength -ge $Recos.MinLengthStandard -and -not ($context.IsRunAsAdmin)) {
                    $statusLength = "PASS"
                    $msgLength = "Conforme Standard (12+ chars). Pourrait être amélioré à 15 pour les admins."
                    break
                }
                Default {
                    $statusLength = "FAIL"
                    $msgLength = "/!\ NON CONFORME : La longueur ($currentMinLength) est inférieur au minimum ANSSI (12)."
                }
            }

            # --- Complexité ---
            # Switch simple sur la valeur (0 ou 1)
            switch ($currentComplexity) {
                1 { 
                    $statusComplexity = "PASS"
                    $msgComplexity = "Complexité activée."
                }
                Default { 
                    $statusComplexity = "FAIL"
                    $msgComplexity = "/!\ RISQUE : La complexité des mots de passe n'est pas forcée."
                }
            }

            # --- Verrouillage ---
            switch ($currentLockout) {
                0 { 
                    $statusLockout = "FAIL"
                    $msgLockout = "/!\ RISQUE : Le verrouillage de compte est désactivé (Bruteforce possible illimité). Considérer de l'activer."
                }
                { $_ -gt 0 -and $_ -le 3 } { 
                    # Ici $_ représente la valeur testée ($currentLockout)
                    $statusLockout = "PASS"
                    $msgLockout = "Protection active ($currentLockout échecs avant blocage)."
                }
                Default { 
                    $statusLockout = "WARNING"
                    $msgLockout = "Seuil élevé ($currentLockout). Un attaquant a beaucoup d'essais avant blocage. Considérer réduire à 3."
                }
            }

            # 4. Nettoyage
            Remove-Item -Path $tempFile -ErrorAction SilentlyContinue

            # 5. Construction de l'objet résultat
            return [PSCustomObject]@{
                Check           = "Password Policy"
                
                MinLengthVal    = $currentMinLength
                MinLengthStatus = $statusLength
                MinLengthReco   = $msgLength

                ComplexityVal   = $currentComplexity
                ComplexityStatus= $statusComplexity
                ComplexityReco  = $msgComplexity

                LockoutVal      = $currentLockout
                LockoutStatus   = $statusLockout
                LockoutReco     = $msgLockout

                # Résumé global
                GlobalStatus    = if ("FAIL" -in ($statusLength, $statusComplexity, $statusLockout)) { "FAIL" } else { "PASS" }
                
                Timestamp       = (Get-Date)
            }
        }
        catch {
            Write-Error "Erreur audit Politique Mot de Passe : $_"
            return [PSCustomObject]@{ Check = "Password Policy"; Status = "Error"; Error = $_.Exception.Message }
        }
    }
}