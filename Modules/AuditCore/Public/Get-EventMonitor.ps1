function Get-EventForwardingStatus {
    [CmdletBinding()]
    param()
    #Check WEF & Sysmon

    process{

        $Print = [System.Collections.ArrayList]@()

        $WEF = Get-WinEvent -listLog Microsoft-Windows-Forwarding/Operational
        if ($WEF.RecordCount -eq 0) {

            $MyCustomObject = [PSCustomObject]@{
                    Name = 'Windows Event Forwarder'
                    IsEnabled = $false
                }

            [void]$Print.Add($MyCustomObject)

        }else{

            $sub = wecutil es 2>$null
            $MyCustomObject = [PSCustomObject]@{
                    Name = 'Windows Event Forwarder'
                    IsEnabled = $true
                    SubscriptionsCount = ($sub | Measure-Object).Count
                }

            [void]$Print.Add($MyCustomObject) 
        }

        $Sysmon = Get-Service -Name Sysmon -ErrorAction SilentlyContinue
        if ($Sysmon){
        
            $MyCustomObject = [PSCustomObject]@{
                    Name = 'Sysmon'
                    IsEnabled = $true
                }

            [void]$Print.Add($MyCustomObject)

        }else{

            $MyCustomObject = [PSCustomObject]@{
                    Name = 'Sysmon'
                    IsEnabled = $false
                }
        
            [void]$Print.Add($MyCustomObject)
        }


        return $Print

    }
}





function Get-LogAgentStatus {
    [CmdletBinding()]
    param()
    #Check SIEM / Log Server

    process{

        $Print = [System.Collections.ArrayList]@()

        $patterns = 'Splunk','LogRhythm','NXLog','Wazuh','CrowdStrike','Sentinel','Rsyslog','Notepad\+\+','Corsair','Steam','Nvidia'

        $regex = ($patterns -join '|')

        $apps = Get-ItemProperty `
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion

        $found = $apps | Where-Object { $_.DisplayName -match $regex }

        return $found

    }

}
