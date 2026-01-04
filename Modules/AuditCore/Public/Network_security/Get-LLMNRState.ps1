function Get-LLMNRState2 {
    [CmdletBinding()]
    param()

    $llmnrRegPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient'
    $llmnrValue   = $null

    if (Test-Path $llmnrRegPath) {
        $llmnrValue = (Get-ItemProperty -Path $llmnrRegPath -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
    }

    $llmnrStatus = switch ($llmnrValue) {
        1     { 'Enabled via policy (multicast name resolution allowed)' }
        0     { 'Disabled via policy (LLMNR turned off)' }
        $null { 'Enabled by default (no explicit policy, multicast name resolution likely allowed)' }
        default { "Unknown value ($llmnrValue)" }
    }

    $recommendation = switch ($llmnrValue) {
        1 {
            'LLMNR is explicitly enabled via policy; consider disabling it (EnableMulticast = 0) to reduce name resolution spoofing attacks.'
        }
        0 {
            'LLMNR is disabled via policy; this is recommended to reduce spoofing and man-in-the-middle risks.'
        }
        $null {
            'No explicit LLMNR policy found; configure EnableMulticast = 0 (Turn off multicast name resolution) to disable LLMNR.'
        }
        default {
            'Review LLMNR configuration and align it with the hardening baseline (typically disabled on corporate networks).'
        }
    }

    if($llmnrStatus -ne 1){

        $Xml = [pscustomobject]@{
                    Category    = 'LLMNR'
                    Description = 'Disable LLMNR in registry'
                    Command     = 'New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" | Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1'
       }

    }

    $LLMNR = [PSCustomObject]@{
        LLMNR_Status     = $llmnrStatus
        EnableMulticast  = if ($llmnrValue) { $llmnrValue } else { 'N/A' }
        Recommendation   = $recommendation
    }

    $Output = [PSCustomObject]@{
        Value = $LLMNR
        Xml = $Xml
    }

    Return $Output

}
