function Get-NetworkProtectionStatus {
    [CmdletBinding()]
    param()

    $mp = Get-MpPreference

    $mode = switch ($mp.EnableNetworkProtection) {
        0 {'Off'}
        1 {'Block'}
        2 {'Audit'}
        $null {'NotConfigured'}
        default {"Unknown ($($mp.EnableNetworkProtection))"}
    }

    $NP = [pscustomobject]@{
        EnableNetworkProtection = ($mp.EnableNetworkProtection -ge 1)
        Mode                    = $mode
    }

    Return $NP
}
