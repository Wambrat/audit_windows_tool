function Get-LastReboot {
    [CmdletBinding()]
    param()

    process {
        $os       = Get-CimInstance -ClassName Win32_OperatingSystem

        $now      = Get-Date
        $lastBoot = $os.LastBootUpTime
        $uptime   = $now - $lastBoot

        # 1 = Workstation, 2 = Domain Controller, 3 = Server
        $isWorkstation = ($os.ProductType -eq 1)
        $role          = if ($isWorkstation) { 'Workstation' } else { 'Server' }

        $uptimeText = "{0} days {1} hours {2} minutes" -f `
            $uptime.Days, $uptime.Hours, $uptime.Minutes

        # Thresholds (example):
        # - Workstation: warn if > 30 days
        # - Server:      warn if > 90 days
        $thresholdDays = if ($isWorkstation) { 30 } else { 90 }

        if ($uptime.Days -gt $thresholdDays) {
            $recommendation = if ($isWorkstation) {
                "Cette station de travail n'a pas ete redemarree depuis longtemps (>30 jours). Planifiez un redemarrage pour assurer que les correctifs et les changements de configuration sont pleinement appliques."
            } else {
                "Ce serveur n'a pas ete redemarre depuis longtemps (>90 jours). Verifiez l'etat des correctifs et planifiez une fenetre de maintenance pour redemarrer et appliquer les mises a jour en attente."
            }
        }
        else {
            $recommendation = if ($isWorkstation) {
                "Le temps d'activite de la station de travail est dans la plage attendue ; assurez-vous de redemarrages reguliers apres les cycles de correctifs."
            } else {
                "Le temps d'activite du serveur est dans la plage attendue ; assurez-vous que les redemarrages sont effectues apres les cycles de correctifs majeurs."
            }
        }

        [pscustomobject]@{
            ComputerRole  = $role
            LastBootTime  = $lastBoot
            Uptime        = $uptimeText
            UptimeDays    = $uptime.Days
            ThresholdDays = $thresholdDays
            Recommendation = $recommendation
        }
    }
}

