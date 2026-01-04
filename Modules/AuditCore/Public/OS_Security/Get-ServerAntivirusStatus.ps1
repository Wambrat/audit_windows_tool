function Get-ServerAntivirusStatus {
    [CmdletBinding()]
    param ()

    $antivirusStatus = @()

    # Determine if this machine is a domain controller (DomainRole >= 4)
    $cs   = Get-WmiObject Win32_ComputerSystem
    $role = $cs.DomainRole
    $isDomainController = ($role -ge 4)

    # Defender preferences (realtime monitoring)
    $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
    $rtDisabled = $mpPref.DisableRealtimeMonitoring

    # Check Microsoft Defender Antivirus service
    $defenderService = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
    if ($defenderService) {

        $serviceRunning   = ($defenderService.Status -eq 'Running')
        $rtMonitoringOn   = ($rtDisabled -eq $false)
        $overallProtected = $serviceRunning -and $rtMonitoringOn

        $recommendation = if (-not $serviceRunning) {
            'Microsoft Defender service is not running; start the service or verify that another supported AV/EDR solution is active.'
        }
        elseif (-not $rtMonitoringOn) {
            'Microsoft Defender real-time monitoring is disabled (DisableRealtimeMonitoring = 1); enable it unless another real-time AV/EDR is providing equivalent protection.'
        }
        else {
            if ($isDomainController) {
                'On domain controllers, validate Defender configuration, exclusions and hardening according to your security baseline and vendor guidance.'
            } else {
                'Defender real-time monitoring is enabled; ensure cloud-based protection and exclusions are configured according to your baseline.'
            }
        }

        $antivirusStatus += [PSCustomObject]@{
            Name               = 'Microsoft Defender Antivirus'
            Present            = $true
            ServiceRunning     = $serviceRunning
            RealtimeMonitoring = $rtMonitoringOn
            OverallProtected   = $overallProtected
            IsDomainController = $isDomainController
            Description        = 'Built-in Microsoft antivirus service.'
            Recommendation     = $recommendation
        }
    }

    # Detect other AV / EDR related services
    $avPattern = '(Antivirus|Defend|Symantec|McAfee|TrendMicro|CrowdStrike|ESET|Sophos|Kaspersky|SentinelOne)'
    $avServices = Get-CimInstance -ClassName Win32_Service |
                  Where-Object { $_.DisplayName -match $avPattern -or $_.Name -match $avPattern }

    foreach ($service in $avServices) {

        # Avoid double-reporting Defender if already handled above
        if ($defenderService -and $service.Name -eq 'WinDefend') { continue }

        $isRunning = ($service.State -eq 'Running')

        $description = 'Third-party antivirus / EDR related service detected.'
        $recommendation = if ($isDomainController) {
            'This machine is a domain controller; many hardening guides recommend avoiding or strictly limiting third-party AV/EDR here. Validate vendor guidance and your internal baseline.'
        } else {
            'Verify this AV/EDR agent is correctly configured and that only one primary real-time protection engine is active to avoid conflicts.'
        }

        $antivirusStatus += [PSCustomObject]@{
            Name               = $service.DisplayName
            ServiceName        = $service.Name
            Present            = $true
            ServiceRunning     = $isRunning
            RealtimeMonitoring = $null  # unknown for third-party
            OverallProtected   = $isRunning
            IsDomainController = $isDomainController
            Description        = $description
            Recommendation     = $recommendation
        }
    }

    if (-not $antivirusStatus) {
        $antivirusStatus += [PSCustomObject]@{
            Name               = 'No antivirus detected'
            ServiceName        = $null
            Present            = $false
            ServiceRunning     = $false
            RealtimeMonitoring = $false
            OverallProtected   = $false
            IsDomainController = $isDomainController
            Description        = 'No antivirus or EDR-related services detected on this host.'
            Recommendation     = 'Deploy and enable at least one supported antivirus/EDR solution on this server according to your security baseline.'
        }
    }

    return $antivirusStatus
}
