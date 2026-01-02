function Get-SMBSharesAudit {
    [CmdletBinding()]
    param()

    process{

        $sharesAccess = Get-SmbShare | ForEach-Object {

            Get-SmbShareAccess -Name $_.Name

            if (-not $sharesAccess) {
                Write-Warning "Aucun partage SMB n'a pu être récupéré."
                return $null
            }            
                
            if ($_.AccountName -eq 'Everyone','Tout le monde' -and $_.AccessControlType -eq 'Allow') {
                Write-Host 'Attention : Le partage SMB "'$($_.Name)'" est accessible par "Tout le monde".' -ForegroundColor Red
                Write-Host "Vérification des droits NTFS du groupe 'Tout le monde' sur le répertoire partagé..." -ForegroundColor Yellow
                $NTFSAudit = Get-NTFSAudit -Path $_.Path -User 'Everyone'
                if ($NTFSAudit.IsFullControl -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits Full Control sur le répertoire partagé." -ForegroundColor Red
                    Write-Host "Le compte invité est activé sur ce système, le partage est accessible sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanWrite -eq $true -and $NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en lecture et écriture sur le répertoire partagé." -ForegroundColor Red
                    Write-Host "Le compte invité est activé sur ce système, le partage est accessible en lecture écriture sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanWrite -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en écriture sur le répertoire partagé." -ForegroundColor Red
                    Write-Host "Le compte invité est activé sur ce système, le partage est accessible en écriture sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en lecture sur le répertoire partagé." -ForegroundColor Yellow
                    Write-Host "Le compte invité est activé sur ce système, le partage est accessible en lecture sans mot de passe" -ForegroundColor Yellow
                } elseif ($NTFSAudit.RawRights -eq 0 -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits personnalisés sur le répertoire partagé." -ForegroundColor Yellow
                    Write-Host "Le compte invité est activé sur ce système, le partage est possiblement accessible sans mot de passe" -ForegroundColor Yellow
                } else {
                    Write-Host "Le groupe 'Tout le monde' ne dispose pas de droits de lecture ou écriture sur le répertoire partagé." -ForegroundColor Green
                }
            }
        } 
    }
}