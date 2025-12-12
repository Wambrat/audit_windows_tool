function Get-ControlledFolderAccessStatus {
    [CmdletBinding()]
    param()

    $mp = Get-MpPreference

    $mode = switch ($mp.EnableControlledFolderAccess) {
        0 {'Off'}
        1 {'Block'}
        2 {'Audit'}
        3 {'Block disk modification only'}
        4 {'Audit disk modification only'}
        $null {'NotConfigured'}
        default {"Unknown ($($mp.EnableControlledFolderAccess))"}
    }


    $CFA = [pscustomobject]@{
        EnableControlledFolderAccess = $mp.EnableControlledFolderAccess
        Mode                         = $mode
    }

    Return $CFA

}
