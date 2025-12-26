function Get-InstalledApplications {
    [CmdletBinding()]
    param()

    $Paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $AppList = foreach ($path in $Paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object @{n = 'Name'           ; e = { $_.DisplayName     }},
                          @{n = 'Version'        ; e = { $_.DisplayVersion   }},
                          @{n = 'Publisher'      ; e = { $_.Publisher        }},
                          @{n = 'InstallLocation'; e = { $_.InstallLocation  }}
    }

    $AppList | Sort-Object Name, Version
}


function Get-AppUpgrade {
    [CmdletBinding()]
    param()

    # Ensure WinGet client is available (basic check)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Warning 'WinGet CLI is not available on this system. Install App Installer / WinGet before using this function.'
        return
    }

    $upgradable = Get-WinGetPackage -ErrorAction SilentlyContinue |
        Where-Object { $_.IsUpdateAvailable -eq $true } |
        Select-Object Name, InstalledVersion, AvailableVersions

    return $upgradable
}
