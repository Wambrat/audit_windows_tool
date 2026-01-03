function Get-EventForwardingStatus {
    [CmdletBinding()]
    param()
    # Check Windows Event Forwarding (WEF) and Sysmon

    process {
        $Print = [System.Collections.ArrayList]@()

        # --- Windows Event Forwarding (WEF) ---
        $WEF = Get-WinEvent -ListLog Microsoft-Windows-Forwarding/Operational -ErrorAction SilentlyContinue

        if (-not $WEF -or $WEF.RecordCount -eq 0) {
            $MyCustomObject = [PSCustomObject]@{
                Name              = 'Windows Event Forwarding'
                IsEnabled         = $false
                SubscriptionsCount= 0
                Comment           = 'No events found in the Microsoft-Windows-Forwarding/Operational log.'
                Recommendation    = 'Configure Windows Event Forwarding (WEF) subscriptions to send critical security logs to a central collector/SIEM.'
            }
            [void]$Print.Add($MyCustomObject)
        }
        else {
            $sub = wecutil es 2>$null
            $MyCustomObject = [PSCustomObject]@{
                Name               = 'Windows Event Forwarding'
                IsEnabled          = $true
                SubscriptionsCount = ($sub | Measure-Object).Count
                Comment            = 'Windows Event Forwarding log is present and contains events.'
                Recommendation     = 'Review WEF subscriptions to ensure critical security logs (security, Sysmon, PowerShell, etc.) are forwarded to a central collector.'
            }
            [void]$Print.Add($MyCustomObject)
        }


        $Sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        if ($Sysmon) {
            $MyCustomObject = [PSCustomObject]@{
                Name           = 'Sysmon'
                IsEnabled      = ($Sysmon.Status -eq 'Running')
                Comment        = "Sysmon service is installed and current status is '$($Sysmon.Status)'."
                Recommendation = if ($Sysmon.Status -eq 'Running') {
                    'Ensure Sysmon uses a hardened configuration file and that events are forwarded to a SIEM or central log collector.'
                } else {
                    'Consider starting and configuring Sysmon on this host to improve process and network telemetry.'
                }
            }
        }
        else {
            $MyCustomObject = [PSCustomObject]@{
                Name           = 'Sysmon'
                IsEnabled      = $false
                Comment        = 'Sysmon service is not installed on this host.'
                Recommendation = 'Consider deploying Sysmon with a hardened configuration on critical servers and workstations for advanced security logging.'
            }
        }
        [void]$Print.Add($MyCustomObject)

        return $Print
    }
}


function Get-LogAgentStatus {
    [CmdletBinding()]
    param()

    process {
        $Print = [System.Collections.ArrayList]@()

        $patterns = 'Splunk','LogRhythm','NXLog','Wazuh','CrowdStrike','Sentinel','Rsyslog'
        $regex    = ($patterns -join '|')

        $apps = Get-ItemProperty `
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion

        $found = $apps | Where-Object { $_.DisplayName -match $regex }

        if ($found) {
            foreach ($app in $found) {
                $isLogAgent = $app.DisplayName -match 'Splunk|LogRhythm|NXLog|Wazuh|CrowdStrike|Sentinel|Rsyslog'

                $obj = [pscustomobject]@{
                    DisplayName      = $app.DisplayName
                    DisplayVersion   = $app.DisplayVersion
                    IsLogAgent       = $isLogAgent
                    Comment          = if ($isLogAgent) {
                                           'Potential SIEM/logging agent detected on this host.'
                                       } else {
                                           'Application matched the regex pattern but is not a logging agent (likely noise).'
                                       }
                    Recommendation   = if ($isLogAgent) {
                                           'Verify that this log agent is correctly configured to send security-relevant logs to the central SIEM.'
                                       } else {
                                           'Review detection patterns if too many non-logging applications are matched.'
                                       }
                }
                [void]$Print.Add($obj)
            }
        }
        else {
            $obj = [pscustomobject]@{
                DisplayName      = $null
                DisplayVersion   = $null
                IsLogAgent       = $false
                Comment          = 'No known SIEM or log collector agents detected based on the configured patterns.'
                Recommendation   = 'Ensure at least one log forwarding or SIEM agent is installed and configured on critical systems.'
            }
            [void]$Print.Add($obj)
        }

        return $Print
    }
}
