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
            "Le service Microsoft Defender n'est pas en cours d'execution ; demarrez le service ou verifiez qu'une autre solution AV/EDR prise en charge est active."
        }
        elseif (-not $rtMonitoringOn) {
            "La surveillance en temps reel de Microsoft Defender est desactivee (DisableRealtimeMonitoring = 1) ; activez-la a moins qu'une autre solution AV/EDR en temps reel ne fournisse une protection equivalente."
        }
        else {
            if ($isDomainController) {
                "Sur les controlleurs de domaine, validez la configuration de Defender, les exclusions et le durcissement selon votre base de securite et les recommandations du fournisseur."
            } else {
                "La surveillance en temps reel de Defender est activee ; assurez-vous que la protection basee sur le cloud et les exclusions sont configurees selon votre base de securite."
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
            "Cette machine est un controlleur de domaine ; de nombreux guides de durcissement recommandent d'eviter ou de limiter strictement les solutions AV/EDR tierces ici. Validez les conseils du fournisseur et votre base interne."
        } else {
            "Confirmez que cet agent AV/EDR est correctement configure et qu'un seul moteur de protection en temps reel principal est actif pour eviter les conflits."
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
            Description        = "Pas d'antivirus ou de services EDR detectes sur cet hote."
            Recommendation     = "Deployez et activez au moins une solution antivirus/EDR prise en charge sur ce serveur selon votre base de securite."
        }
    }

    return $antivirusStatus
}

