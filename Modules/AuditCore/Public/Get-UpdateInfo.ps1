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


    process{

        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $osinfo = [pscustomobject]@{
            Caption       = $os.Caption          
            Version       = $os.Version          
            BuildNumber   = $os.BuildNumber
            InstallDate   = $os.InstallDate
        }

        return $osinfo
    }


}


function Get-UpdateSource {
    [CmdletBinding()]
    param()

    process{

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    
        $result = "Windows Update (Microsoft Update)"

        if (Test-Path $regPath) {

            $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        
            if ($values.UseWUServer -eq 1) {
            
                $wsusServer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue).WUServer


                if ($wsusServer) {

                    if ($wsusServer -like "https://*") {
                        $result = "WSUS sécurisé (HTTPS) : $wsusServer"
                    } else {
                        $result = "WSUS NON sécurisé (HTTP détecté) : $wsusServer"
                    }

                } else {
                    $result = "WSUS (Serveur non défini)"
                }
            }
        }

        return $result

    }

}