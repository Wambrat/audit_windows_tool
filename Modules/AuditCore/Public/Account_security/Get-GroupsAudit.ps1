function Get-GroupsAudit {
    [CmdletBinding()]
    param()

    process{

        $groups = Get-LocalGroup -ErrorAction SilentlyContinue
        

        if (-not $groups) {
            Write-Warning "Aucun groupe local n'a pu etre recupere."
            return $null
        }

        if ($groups.Name -contains 'Administrateurs') {
            Write-Host "Le groupe 'Administrateurs' est present sur ce systeme." -ForegroundColor Green
            $admingroup = 'Administrateurs'
        } elseif ($groups.Name -contains 'Administrators') {
            Write-Host "Le groupe 'Administrators' est present sur ce systeme." -ForegroundColor Green
            $admingroup = 'Administrators'
        } else {
            Write-Host "Le groupe 'Administrateurs' n'a pas ete trouve sur ce systeme." -ForegroundColor Red
        }

        $adminmembers = Get-LocalGroupMember -Group $admingroup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

        return [PSCustomObject]@{
            GroupName = $admingroup
            MembersCount   = $adminmembers.Count
            Members        = $adminmembers
        }    
    }
}
