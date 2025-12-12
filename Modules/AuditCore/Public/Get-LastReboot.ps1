function Get-LastReboot {
    [CmdletBinding()]
    param()

    process{

        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $Date = Get-Date
        $lastBoot = $os.LastBootUpTime
        $LastReboot = [pscustomobject]@{
            LastBootTime   = $lastBoot
            Uptime = (($Date - $lastBoot).Hours).ToString() + ' Hours'
        }

        Return $LastReboot
    }

}
