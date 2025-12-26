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
                    Recommendation = 'Log is not available or not enabled; ensure this log is configured if required by your monitoring and audit policy.'
                }
                [void]$Print.Add($MyCustomObject)
                continue
            }

            $maxMB  = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            $sizeOK = $null
            $target = if ($reco.ContainsKey($log.LogName)) { $reco[$log.LogName] } else { $null }

            if ($target -ne $null) {
                $sizeOK = $maxMB -ge $target
            }

            # Build recommendation text
            if ($sizeOK -eq $false) {
                $recText = "Current maximum size ($maxMB MB) is below recommended threshold ($target MB) for this log; increase log size to avoid early overwrites."
            }
            elseif ($sizeOK -eq $true) {
                $recText = "Current maximum size ($maxMB MB) meets or exceeds the recommended threshold ($target MB)."
            }
            else {
                $recText = "No specific size recommendation defined for this log; review retention requirements and adjust size accordingly."
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
