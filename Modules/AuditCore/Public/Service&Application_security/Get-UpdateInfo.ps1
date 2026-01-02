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
            return 'No policy key found: using default Windows Update behavior'
        }

        $auValues  = Get-ItemProperty -Path $auPath -ErrorAction SilentlyContinue
        $wuValues  = Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue

        if ($auValues.UseWUServer -eq 1) {

            $wsusServer = $wuValues.WUServer

            if ($wsusServer) {
                if ($wsusServer -like 'https://*') {
                    return "WSUS secured (HTTPS): $wsusServer"
                } else {
                    return "WSUS NOT secured (HTTP detected): $wsusServer"
                }
            } else {
                return 'WSUS configured (UseWUServer=1) but WUServer is not defined'
            }
        }

        return 'Windows Update (Microsoft Update)'
    }
}
