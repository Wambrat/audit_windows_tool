function Get-SmartAppControlStatus {
    [CmdletBinding()]
    param()

    $policyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    $val = (Get-ItemProperty -Path $policyPath -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState

    switch ($val) {
        0 { $mode = 'Off' }
        1 { $mode = 'On' }
        2 { $mode = 'Evaluation' }
        $null { $mode = 'NotConfigured' }
        default { $mode = "Unknown ($val)" }
    }

    $SmartAppState = [pscustomobject]@{

        SmartApp_State = $mode

    }

    Return $SmartAppState

}
