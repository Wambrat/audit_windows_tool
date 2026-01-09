function Get-InstalledKB {
    [CmdletBinding()]
    param()

    process{
        
        $kblist = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Sort-Object InstalledOn -Descending

        return $kblist

    }
    

}

function Get-OSVersionInfo {
    [CmdletBinding()]
    param()

    process {
        $os   = Get-CimInstance -ClassName Win32_OperatingSystem
        $ubr  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR

        [pscustomobject]@{
            Caption       = $os.Caption
            Version       = $os.Version
            FullVersion   = "$($os.Version).$ubr"
            BuildNumber   = $os.BuildNumber
            InstallDate   = $os.InstallDate
        }
    }
}



function Get-UpdateSource {
    [CmdletBinding()]
    param()

    process {
        $basePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $auPath   = Join-Path $basePath 'AU'

        if (-not (Test-Path $auPath)) {
            return 'Aucune cle de strategie trouvee : utilisation du comportement par defaut de Windows Update'
        }

        $auValues  = Get-ItemProperty -Path $auPath -ErrorAction SilentlyContinue
        $wuValues  = Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue

        if ($auValues.UseWUServer -eq 1) {

            $wsusServer = $wuValues.WUServer

            if ($wsusServer) {
                if ($wsusServer -like 'https://*') {
                    return "WSUS securise (HTTPS) : $wsusServer"
                } else {
                    return "WSUS NON securise (HTTP detecte) : $wsusServer"
                }
            } else {
                return "WSUS configure (UseWUServer=1) mais WUServer n'est pas defini"
            }
        }

        return 'Windows Update (Microsoft Update)'
    }
}

