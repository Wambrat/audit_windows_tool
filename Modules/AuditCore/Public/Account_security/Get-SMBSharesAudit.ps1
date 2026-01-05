function Get-SMBSharesAudit {
    [CmdletBinding()]
    param()

    process{

        $shares = Get-SmbShare

        if (-not $shares) {
            Write-Warning "Aucun partage SMB n'a pu etre recupere."
            return $null
        }

        $shares | ForEach-Object {
            $share = $_
            $sharesAccess = Get-SmbShareAccess -Name $share.Name
                
            $sharesAccess | Where-Object { $_.AccountName -eq 'Tout le monde' -and $_.AccessControlType -eq 'Allow' } | ForEach-Object {
                Write-Host "`nAttention : Le partage SMB '"$($share.Name)"' est accessible par 'Tout le monde'. Chemin du partage : "$($share.Path) -ForegroundColor Red
                Write-Host "Verification des droits NTFS du groupe 'Tout le monde' sur le repertoire partage..." -ForegroundColor Yellow
                $NTFSAudit = Get-NTFSAudit -Path $share.Path -User 'Tout le monde'
                if ($NTFSAudit.IsFullControl -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits Full Control sur le repertoire partage." -ForegroundColor Red
                    Write-Host "Le compte invite est active sur ce systeme, le partage est accessible sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanWrite -eq $true -and $NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en lecture et ecriture sur le repertoire partage." -ForegroundColor Red
                    Write-Host "Le compte invite est active sur ce systeme, le partage est accessible en lecture ecriture sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanWrite -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en ecriture sur le repertoire partage." -ForegroundColor Red
                    Write-Host "Le compte invite est active sur ce systeme, le partage est accessible en ecriture sans mot de passe" -ForegroundColor Red
                } elseif ($NTFSAudit.CanRead -eq $true -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits en lecture sur le repertoire partage." -ForegroundColor Yellow
                    Write-Host "Le compte invite est active sur ce systeme, le partage est accessible en lecture sans mot de passe" -ForegroundColor Yellow
                } elseif ($NTFSAudit.RawRights -eq 0 -and $localUserAudit.GuestEnabled -eq $true) {
                    Write-Host "Le groupe 'Tout le monde' dispose de droits personnalises sur le repertoire partage." -ForegroundColor Yellow
                    Write-Host "Le compte invite est active sur ce systeme, le partage est possiblement accessible sans mot de passe" -ForegroundColor Yellow
                } elseif ($localUserAudit.GuestEnabled -eq $false) {
                    Write-Host "Le compte invite est desactive sur ce systeme, le partage n'est pas accessible sans mot de passe." -ForegroundColor Green
                } else {
                    Write-Host "Le groupe 'Tout le monde' ne dispose pas de droits de lecture ou ecriture sur le repertoire partage." -ForegroundColor Green
                }
            }
        }
    }
}
