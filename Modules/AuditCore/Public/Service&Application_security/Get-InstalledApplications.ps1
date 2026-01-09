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

    if ($context.OSVersion -match "Windows 7|Windows 8|Windows 8.1|Windows Server 2008|Windows Server 2012|Windows Server 2016|Windows Server 2019") {
        return $null
    }
    # Ensure WinGet client is available (basic check)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Warning 'WinGet CLI n''est pas disponible sur ce systeme. Installez App Installer / WinGet avant d''utiliser cette fonction.'
    }

    # Verifie si Get-WinGetPackage est disponible, sinon propose d'installer le module
    if (-not (Get-Command "Get-WinGetPackage" -ErrorAction SilentlyContinue)) {
        
        Write-Warning "La commande 'Get-WinGetPackage' est introuvable ! Le module 'Microsoft.WinGet.Client' n'est pas installe."
        $reponse = Read-Host "Voulez-vous installer le module 'Microsoft.WinGet.Client' ? (O/N)"

        if ($reponse -match "^[oO]") {
            Write-Host "Installation en cours..." -ForegroundColor Cyan
            try {
                # Installe pour l'utilisateur courant pour eviter les soucis de droits admin
                Install-Module -Name Microsoft.WinGet.Client -Scope CurrentUser -Force
                # Importe le module immediatement pour qu'il soit utilisable tout de suite
                Import-Module Microsoft.WinGet.Client
                Write-Host "Installation reussie !" -ForegroundColor Green
            }
            catch {
                Write-Error "Une erreur est survenue : $_"
            }
        }
        else {
            Write-Host "Installation annulee par l'utilisateur." -ForegroundColor Yellow
        }
    }

    $upgradable = Get-WinGetPackage -ErrorAction SilentlyContinue |
        Where-Object { $_.IsUpdateAvailable -eq $true } |
        Select-Object Name, InstalledVersion, AvailableVersions

    return $upgradable
}

