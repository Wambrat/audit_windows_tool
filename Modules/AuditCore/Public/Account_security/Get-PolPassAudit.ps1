<#
.SYNOPSIS
    Audite la politique de mot de passe locale et de verrouillage.

.DESCRIPTION
    Utilise l'outil natif 'secedit' pour exporter la configuration de securite actuelle
    et la compare aux recommandations de l'ANSSI via des switchs.
    - Longueur minimale (12 min, 15 recommande pour admins).
    - Complexite (Activee).
    - Verrouillage compte (3 tentatives recommandees).

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

            if (-not (Test-Path $tempFile)) { throw "Impossible de generer le fichier d'export SecEdit." }

            $content = Get-Content -Path $tempFile -Encoding Unicode -Raw

            # Parsing Regex (Inchange)
            $null = $content -match "MinimumPasswordLength\s*=\s*(\d+)"
            $currentMinLength = if ($Matches[1]) { [int]$Matches[1] } else { 0 }

            $null = $content -match "PasswordComplexity\s*=\s*(\d+)"
            $currentComplexity = if ($Matches[1]) { [int]$Matches[1] } else { 0 }

            $null = $content -match "LockoutBadCount\s*=\s*(\d+)"
            $currentLockout = if ($Matches[1]) { [int]$Matches[1] } else { 0 }


            # 3. Analyse de Conformite avec SWITCH

            # --- Longueur ---
            # On switch sur $true pour evaluer les conditions mathematiques
            switch ($true) {
                ($currentMinLength -ge $Recos.MinLengthAdmin -and ($context.IsRunAsAdmin)) {
                    $statusLength = "EXCELLENT"
                    $msgLength = "Conforme Admin (15+ chars)."
                    break # On sort des qu'on trouve, pour ne pas tester la suite
                }
                ($currentMinLength -ge $Recos.MinLengthStandard -and -not ($context.IsRunAsAdmin)) {
                    $statusLength = "PASS"
                    $msgLength = "Conforme Standard (12+ chars). Pourrait etre ameliore a 15 pour les admins."
                    break
                }
                Default {
                    $statusLength = "FAIL"
                    $msgLength = "/!\ NON CONFORME : La longueur ($currentMinLength) est inferieur au minimum ANSSI (12)."
                }
            }

            # --- Complexite ---
            # Switch simple sur la valeur (0 ou 1)
            switch ($currentComplexity) {
                1 { 
                    $statusComplexity = "PASS"
                    $msgComplexity = "Complexite activee."
                }
                Default { 
                    $statusComplexity = "FAIL"
                    $msgComplexity = "/!\ RISQUE : La complexite des mots de passe n'est pas forcee."
                }
            }

            # --- Verrouillage ---
            switch ($currentLockout) {
                0 { 
                    $statusLockout = "FAIL"
                    $msgLockout = "/!\ RISQUE : Le verrouillage de compte est desactive (Bruteforce possible illimite). Considerer de l'activer."
                }
                { $_ -gt 0 -and $_ -le 3 } { 
                    # Ici $_ represente la valeur testee ($currentLockout)
                    $statusLockout = "PASS"
                    $msgLockout = "Protection active ($currentLockout echecs avant blocage)."
                }
                Default { 
                    $statusLockout = "WARNING"
                    $msgLockout = "Seuil eleve ($currentLockout). Un attaquant a beaucoup d'essais avant blocage. Considerer reduire a 3."
                }
            }

            # 4. Nettoyage
            Remove-Item -Path $tempFile -ErrorAction SilentlyContinue

            # 5. Construction de l'objet resultat
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

                # Resume global
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
