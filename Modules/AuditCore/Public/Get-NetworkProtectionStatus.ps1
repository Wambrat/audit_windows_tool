function Get-NetworkProtectionStatus {
    [CmdletBinding()]
    param()

    $mp = Get-MpPreference

    $mode = switch ($mp.EnableNetworkProtection) {
        0     { 'Off' }
        1     { 'Block' }
        2     { 'Audit' }
        $null { 'NotConfigured' }
        default { "Unknown ($($mp.EnableNetworkProtection))" }
    }

    $recommendation = switch ($mp.EnableNetworkProtection) {
        1 {
            'Network Protection is in Block mode; regularly review alerts and ensure business applications are not impacted.'
        }
        2 {
            'Network Protection is in Audit mode; review logged events and plan to move to Block mode on critical endpoints.'
        }
        0 {
            'Network Protection is disabled; enable it in Audit mode first, then Block mode to prevent access to malicious domains and IPs.'
        }
        $null {
            'Network Protection is not configured; define a policy (Audit/Block) via GPO, Intune, or Set-MpPreference.'
        }
        default {
            'Review the current Network Protection configuration and align it with your Defender hardening baseline.'
        }
    }

    $NP = [pscustomobject]@{
        EnableNetworkProtection = ($mp.EnableNetworkProtection -ge 1)
        Mode                    = $mode
        RawValue                = $mp.EnableNetworkProtection
        Recommendation          = $recommendation
    }

    return $NP
}
