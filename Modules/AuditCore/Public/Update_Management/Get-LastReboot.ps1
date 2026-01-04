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
                'This workstation has not been rebooted for a long time (>30 days). Plan a reboot to ensure patches and configuration changes are fully applied.'
            } else {
                'This server has not been rebooted for a long time (>90 days). Review patch status and plan a maintenance window to reboot and apply pending updates.'
            }
        }
        else {
            $recommendation = if ($isWorkstation) {
                'Workstation uptime is within the expected range; ensure regular reboots after patch cycles.'
            } else {
                'Server uptime is within the expected range; ensure reboots are performed after major patch cycles.'
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
