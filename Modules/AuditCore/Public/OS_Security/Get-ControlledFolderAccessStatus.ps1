function Get-ControlledFolderAccessStatus {
    [CmdletBinding()]
    param()

    # Get current Microsoft Defender Controlled Folder Access configuration
    $mp = Get-MpPreference

    $mode = switch ($mp.EnableControlledFolderAccess) {
        0     { 'Off' }
        1     { 'Block' }
        2     { 'Audit' }
        3     { 'Block disk modification only' }
        4     { 'Audit disk modification only' }
        $null { 'NotConfigured' }
        default { "Unknown ($($mp.EnableControlledFolderAccess))" }
    }

    # Simple recommendation based on current mode
    $recommendation = switch ($mp.EnableControlledFolderAccess) {
        0       {'Consider enabling Controlled Folder Access in Audit mode first to evaluate impact, then move to Block for critical endpoints.'}
        2       {'Review audit events for Controlled Folder Access and plan to switch to Block mode on high-value endpoints once noise is acceptable.'}
        1       {'Ensure the list of protected folders and allowed applications is regularly reviewed to balance security and usability.'}
        3       {'Validate that disk-only protection is sufficient; consider full Block mode for highly sensitive systems.'}
        4       {'Use audit data on disk modifications to decide where stricter Block policies are required.'}
        default {'Review Defender Controlled Folder Access configuration and align it with your ransomware protection strategy.'}
    }

    $CFA = [pscustomobject]@{
        EnableControlledFolderAccess = $mp.EnableControlledFolderAccess
        Mode                         = $mode
        Recommendation               = $recommendation
    }

    return $CFA
}
