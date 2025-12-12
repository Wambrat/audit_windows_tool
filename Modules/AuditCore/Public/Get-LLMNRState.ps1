function Get-LLMNRState {
    [CmdletBinding()]
    param()

    $llmnrRegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    $llmnrValue = $null

    if (Test-Path $llmnrRegPath) {
        $llmnrValue = (Get-ItemProperty $llmnrRegPath -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    }

    $llmnrStatus = switch ($llmnrValue) {
        0 { "Enabled (via policy)" }
        1 { "Disabled (via policy)" }
        $null { "Enabled (By Default)" }
        default { "Unknown" }
    }


    $LLMNR = [PSCustomObject]@{
        LLMNR_Status   = $llmnrStatus
    }

    Return $LLMNR

}
