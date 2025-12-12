function Get-InstalledApplications {
    [CmdletBinding()]
    param()

    process{

        $Paths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $Applist = foreach ($path in $paths) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
            Select-Object @{n='Name';e={$_.DisplayName}},
                          @{n='Version';e={$_.DisplayVersion}},
                          @{n='Publisher';e={$_.Publisher}},
                          @{n='InstallLocation';e={$_.InstallLocation}}
        }

        Return $Applist | Sort-Object Name, Version

    }

}

function Get-AppUpgrade {
    param()

    process{

        $Winget = Get-Package -Name Microsoft.Winget.client
        if(-not $winget){
    
            Install-Package Microsoft.WinGet.Client -Confirm

        }

        $Upgradable = Get-WinGetPackage | Where-Object IsUpdateAvailable -Match True  | Select-Object Name, InstalledVersion, AvailableVersions

        Return $Upgradable

    }

}