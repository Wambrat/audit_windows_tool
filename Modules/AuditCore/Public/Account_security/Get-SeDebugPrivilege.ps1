function Get-Privilege {
    [CmdletBinding()]
    param (
        [string[]]$Privileges = @(
            'SeImpersonatePrivilege',
            'SeInteractiveLogonRight',
            'SeServiceLogonRight',
            'SeBatchLogonRight',
            'SeRemoteInteractiveLogonRight',
            'SeDebugPrivilege',
            'SeTcbPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege',
            'SeAssignPrimaryTokenPrivilege',
            'SeCreateTokenPrivilege',
            'SeLoadDriverPrivilege'
        )
    )

    # Specific recommendations per privilege
    $specificRecos = @{
        'SeImpersonatePrivilege' = "Eviter SeImpersonate."
        'SeInteractiveLogonRight' = "Restreindre 'Log on locally' aux seuls comptes qui en ont vraiment besoin."
        'SeServiceLogonRight' = "Restreindre 'Log on as a service' aux seuls comptes qui en ont vraiment besoin."
        'SeBatchLogonRight' = "Restreindre 'Log on as a batch job' aux seuls comptes qui en ont vraiment besoin."
        'SeRemoteInteractiveLogonRight' = "Interdire 'Allow log on through RDP' aux comptes utilisateurs classiques sur les serveurs ; passer par jump servers / bastions + comptes admin dedies."
        'SeDebugPrivilege' = "Limiter SeDebugPrivilege (Debug programs) => Parce que sinon on peut dump tout meme sans admin."
        'SeTcbPrivilege' = "Limiter SeTcbPrivilege (Act as part of the operating system)."
        'SeBackupPrivilege' = "Limiter SeBackupPrivilege / SeRestorePrivilege (Backup/restore files and directories)."
        'SeRestorePrivilege' = "Limiter SeBackupPrivilege / SeRestorePrivilege (Backup/restore files and directories)."
        'SeAssignPrimaryTokenPrivilege' = "Limiter SeAssignPrimaryTokenPrivilege / SeCreateTokenPrivilege."
        'SeCreateTokenPrivilege' = "Limiter SeAssignPrimaryTokenPrivilege / SeCreateTokenPrivilege."
        'SeLoadDriverPrivilege' = "Limiter SeLoadDriverPrivilege (Load and unload device drivers)."
    }

    # Export local security policy to a temporary file
    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

    $results = @()

    foreach ($privilege in $Privileges) {
        $line = $content | Where-Object { $_ -match "^$privilege" }

        if ($line) {
            $sids = ($line -split '=')[1].Trim()
            $sids = ($sids -split ',')

            $isAdminPresent = ($sids -contains '*S-1-5-32-544')  # Builtin Administrators
            $hasExtraSids   = ($sids | Where-Object { $_ -ne '*S-1-5-32-544' }).Count -gt 0

            $Members = foreach($sid in $sids){
                if($sid -match "^\*S-"){
                    $sid = $sid.Substring(1)
                    ([wmi]"Win32_SID.SID='$sid'").AccountName
                } else {
                    $sid
                }
            }

            $reco = @()

            if ($isAdminPresent -and -not $hasExtraSids) {
                $reco += "$privilege est restreint au groupe Administrateurs integres ; revoir periodiquement les ajouts indesirables."
            }
            elseif ($hasExtraSids) {
                $reco += "D'autres SID ont $privilege ; restreignez ce droit a aussi peu de comptes administrateurs hautement fiables que possible."
            }
            else {
                $reco += "Pas de SID Administrateurs explicite trouve pour $privilege; verifiez que cela est prevu et qu'au moins un groupe d'administration securise a ce droit."
            }

            # Add specific recommendation if exists
            if ($specificRecos.ContainsKey($privilege)) {
                $reco += $specificRecos[$privilege]
            }

            $PrivilegeState = [PSCustomObject]@{
                Privilege      = $privilege
                Configured     = $true
                AssignedTo     = $Members
                IsAdminPresent = $isAdminPresent
                Recommendation = ($reco -join ' ')
            }
        }
        else {
            $reco = " $privilege n'est pas configure explicitement; appliquez une politique qui restreint ce droit a un ensemble minimal de comptes administrateurs."
            if ($specificRecos.ContainsKey($privilege)) {
                $reco += " " + $specificRecos[$privilege]
            }

            $PrivilegeState = [PSCustomObject]@{
                Privilege      = $privilege
                Configured     = $false
                AssignedTo     = $null
                IsAdminPresent = $false
                Recommendation = $reco
            }
        }

        $results += $PrivilegeState
    }

    return $results
}

