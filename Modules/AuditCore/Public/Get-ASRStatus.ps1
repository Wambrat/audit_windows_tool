function Get-ASRStatus {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $mp = Get-MpPreference

    $ids      = $mp.AttackSurfaceReductionRules_Ids
    $actions  = $mp.AttackSurfaceReductionRules_Actions

    if (-not $ids) {
        return [pscustomobject]@{
            RuleId   = $null
            Action   = $null
            Enabled  = $false
            Comment  = 'No ASR rules configured (disabled).'
        }
    }

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $mode = switch ($actions[$i]) {
            0 {'Disabled'}
            1 {'Block'}
            2 {'Audit'}
            6 {'Warn'}
            default {"Unknown ($($actions[$i]))"}
        }

        $ASR= [pscustomobject]@{
            RuleId  = $ids[$i]
            Action  = $mode
            Enabled = ($actions[$i] -eq 1)
        }

        [void]$Print.Add($ASR)

    }

    Return $Print

}
