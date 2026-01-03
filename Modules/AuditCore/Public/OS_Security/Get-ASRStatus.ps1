function Get-ASRStatus {
    [CmdletBinding()]
    param()

    $results = [System.Collections.ArrayList]@()


    $mp = Get-MpPreference

    $ids     = $mp.AttackSurfaceReductionRules_Ids
    $actions = $mp.AttackSurfaceReductionRules_Actions

    if (-not $ids) {
        return [pscustomobject]@{
            RuleId        = $null
            Action        = $null
            Enabled       = $false
            Comment       = 'No ASR rules are currently configured (ASR effectively disabled).'
            Recommendation = 'Enable Microsoft Defender Attack Surface Reduction rules like : 
                - Blocking malicious macros in Office.
                - Preventing the execution of suspicious scripts (PowerShell, JavaScript, etc.).
                - Blocking unauthorized processes from sensitive locations (e.g., %AppData% or %Temp%).
                - Protection against malicious email attachments. '
        }
    }

    for ($i = 0; $i -lt $ids.Count; $i++) {
        $rawAction = $actions[$i]

        $mode = switch ($rawAction) {
            0 { 'Disabled' }
            1 { 'Block' }
            2 { 'Audit' }
            6 { 'Warn' }
            default { "Unknown ($rawAction)" }
        }

        # Simple recommendation based on mode
        $recommendation = switch ($rawAction) {
            0 { 'Consider at least enabling this ASR rule in Audit mode, then switching to Block after validation.' }
            2 { 'Review audit logs for this ASR rule and plan to move it to Block where stable.' }
            6 { 'Monitor user experience for this ASR rule and consider moving to Block on hardened endpoints.' }
            1 { 'Ensure this ASR rule in Block mode has been validated in your environment and is documented.' }
            default { 'Review this ASR rule configuration against Microsoft and internal hardening guidelines.' }
        }

        $ASR = [pscustomobject]@{
            RuleId         = $ids[$i]
            Action         = $mode
            Enabled        = ($rawAction -eq 1)
            Comment        = "ASR rule is currently set to '$mode'."
            Recommendation = $recommendation
        }

        [void]$results.Add($ASR)
    }

    return $results
}
