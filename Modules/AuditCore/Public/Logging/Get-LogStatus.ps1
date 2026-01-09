function Get-LogStatus {
    [CmdletBinding()]
    param()

    process {
        # Recommended minimum sizes (in MB) – adjust per role
        $reco = @{
            'Security'    = 400   # Example: 400 MB on workstations (1 GB+ on servers)
            'Application' = 50
            'System'      = 50
            'Windows PowerShell'                        = 50
            'Microsoft-Windows-PowerShell/Operational' = 200
        }

        $logs = 'Security','System','Application',
                'Windows PowerShell','Microsoft-Windows-PowerShell/Operational'

        $Print = [System.Collections.ArrayList]@()

        foreach ($name in $logs) {
            $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue

            if (-not $log) {
                $MyCustomObject = [PSCustomObject]@{
                    LogName        = $name
                    IsEnabled      = $false
                    RecordCount    = 0
                    MaximumSizeMB  = $null
                    Retention      = $null
                    RecoSizeMB     = if ($reco.ContainsKey($name)) { $reco[$name] } else { $null }
                    IsSizeOK       = $null
                    Recommendation = "Le journal n'est pas disponible ou n'est pas active ; assurez-vous que ce journal est configure si requis par votre politique de surveillance et d'audit."
                }
                [void]$Print.Add($MyCustomObject)
                continue
            }

            $maxMB  = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $sizeOK = $null
            $target = if ($reco.ContainsKey($log.LogName)) { $reco[$log.LogName] } else { $null }

            if ($target) {
                $sizeOK = $maxMB -ge $target
            }

            # Build recommendation text
            if ($sizeOK -eq $false) {
                $recText = "La taille maximale actuelle ($maxMB Mo) est inferieure au seuil recommande ($target Mo) pour ce journal ; augmentez la taille du journal pour eviter les ecrasements precoces."
            }
            elseif ($sizeOK -eq $true) {
                $recText = "La taille maximale actuelle ($maxMB Mo) est superieure ou egale au seuil recommande ($target Mo)."
            }
            else {
                $recText = "Aucune recommandation de taille specifique definie pour ce journal ; revisez les exigences de conservation et ajustez la taille en consequence."
            }

            $MyCustomObject = [PSCustomObject]@{
                LogName        = $log.LogName
                IsEnabled      = $log.IsEnabled
                RecordCount    = $log.RecordCount
                MaximumSizeMB  = $maxMB
                Retention      = $log.LogMode
                RecoSizeMB     = $target
                IsSizeOK       = $sizeOK
                Recommendation = $recText
            }

            [void]$Print.Add($MyCustomObject)
        }

        return $Print
    }
}

