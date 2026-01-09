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
                Comment           = "Pas d'evenements trouves dans le journal Microsoft-Windows-Forwarding/Operational."
                Recommendation    = "Configurez les abonnements Windows Event Forwarding (WEF) pour envoyer les journaux de securite critiques a un collecteur/SIEM central."
            }
            [void]$Print.Add($MyCustomObject)
        }
        else {
            $sub = wecutil es 2>$null
            $MyCustomObject = [PSCustomObject]@{
                Name               = 'Windows Event Forwarding'
                IsEnabled          = $true
                SubscriptionsCount = ($sub | Measure-Object).Count
                Comment            = "Windows Event Forwarding est presente et contient des evenements."
                Recommendation     = "Revoir les abonnements WEF pour vous assurer que les journaux de securite critiques (securite, Sysmon, PowerShell, etc.) sont envoyes a un collecteur central."
            }
            [void]$Print.Add($MyCustomObject)
        }


        $Sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        if ($Sysmon) {
            $MyCustomObject = [PSCustomObject]@{
                Name           = 'Sysmon'
                IsEnabled      = ($Sysmon.Status -eq 'Running')
                Comment        = "Le service Sysmon est installe et le statut actuel est '$($Sysmon.Status)'."
                Recommendation = if ($Sysmon.Status -eq 'Running') {
                    "Assurez-vous que Sysmon utilise un fichier de configuration durci et que les evenements sont transmis a un SIEM ou a un collecteur de journaux central."
                } else {
                    "Envisagez de demarrer et de configurer Sysmon sur cet hote pour ameliorer la telemetrie des processus et du reseau."
                }
            }
        }
        else {
            $MyCustomObject = [PSCustomObject]@{
                Name           = 'Sysmon'
                IsEnabled      = $false
                Comment        = "Le service Sysmon n'est pas installe sur cet hote."
                Recommendation = "Considerez le deploiement de Sysmon avec une configuration durcie sur les serveurs et postes de travail critiques pour une journalisation de securite avancee."
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
                                           "Potentiel SIEM/logging agent detecte sur cet hote."
                                       } else {
                                            "L'application correspond au modele regex mais n'est pas un agent de journalisation (probablement du bruit)."
                                       }
                    Recommendation   = if ($isLogAgent) {
                                           "Verifiez que cet agent de journalisation est correctement configure pour envoyer les journaux pertinents pour la securite au SIEM central."
                                       } else {
                                           "Revoir les modeles de detection si trop d'applications non journalisantes sont correspondantes."
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
                Comment          = "Aucun agent SIEM ou collecteur de journaux connu detecte en fonction des modeles configures."
                Recommendation   = "Assurez-vous qu'au moins un agent de transfert de journaux ou SIEM est installe et configure sur les systemes critiques."
            }
            [void]$Print.Add($obj)
        }

        return $Print
    }
}

