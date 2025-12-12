function Get-DeviceGuardStatus {
    [CmdletBinding()]
    param()

    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

    if (-not $dg) {
        return [pscustomobject]@{
            VirtualizationBasedSecurityStatus          = $null
            UserModeCodeIntegrityPolicyEnforcementStatus = $null
            SecurityServicesConfigured                 = $null
            SecurityServicesRunning                    = $null
            WDAC_Active                                = $false
            VBS_Active                                 = $false
            Source                                     = 'NoDeviceGuardClass'
        }
    }

    $vbsActive  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
    $wdacActive = ($dg.UserModeCodeIntegrityPolicyEnforcementStatus -eq 2)
    

    $cicActive = switch($dg.CodeIntegrityPolicyEnforcementStatus){
        0{"Off"}
        1{"Audit mode"}
        2{"Enforced"}
        Default{"Unknown value"}
    }

    $DGS = [pscustomobject]@{
        CodeIntegrityPolicyEnforcementStatus          = $cicActive
        WDAC_Active                                   = $wdacActive
        VBS_Active                                    = $vbsActive
    }

    Return $DGS
}
