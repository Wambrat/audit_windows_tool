function Get-LogStatus {
    [CmdletBinding()]
    param()

    process{
        $reco = @{
            'Security'    = 400   # Mo postes (1 Go sur serveurs – à adapter)
            'Application' = 50
            'System'      = 50
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
                    RecoSizeMB     = $reco[$name]
                    IsSizeOK       = $null
                }
                [void]$Print.Add($MyCustomObject)
                continue
            }

            $maxMB = [math]::Round($log.MaximumSizeInBytes/1MB,2)
            $sizeOK = $null
            if ($reco.ContainsKey($log.LogName)) {
                $sizeOK = $maxMB -ge $reco[$log.LogName]
            }

            $MyCustomObject = [PSCustomObject]@{
                LogName        = $log.LogName
                IsEnabled      = $log.IsEnabled
                RecordCount    = $log.RecordCount
                MaximumSizeMB  = $maxMB
                Retention      = $log.LogMode
                RecoSizeMB     = $reco[$log.LogName]
                IsSizeOK       = $sizeOK
            }
            [void]$Print.Add($MyCustomObject)
        }
        Return $Print

    }
}
