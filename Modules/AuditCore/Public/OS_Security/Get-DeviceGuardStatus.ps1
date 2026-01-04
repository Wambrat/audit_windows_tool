function Get-DeviceGuardStatus {
    [CmdletBinding()]
    param()

    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
                          -Namespace root\Microsoft\Windows\DeviceGuard `
                          -ErrorAction SilentlyContinue

    if (-not $dg) {
        return [pscustomobject]@{
            VirtualizationBasedSecurityStatus             = $null
            UserModeCodeIntegrityPolicyEnforcementStatus  = $null
            CodeIntegrityPolicyEnforcementStatus          = $null
            SecurityServicesConfigured                    = $null
            SecurityServicesRunning                       = $null
            WDAC_Active                                   = $false
            VBS_Active                                    = $false
            Comment                                       = 'Device Guard / VBS status could not be retrieved (Win32_DeviceGuard not available).'
            Recommendation                                = 'Verify OS version and that Device Guard / VBS is supported and properly configured on this system.'
        }
    }

    # VBS status: 2 = enabled, 0/1 = disabled or not running
    $vbsActive  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
    # WDAC (User Mode Code Integrity): 2 = enforced
    $wdacActive = ($dg.UserModeCodeIntegrityPolicyEnforcementStatus -eq 2)

    $cicActive = switch ($dg.CodeIntegrityPolicyEnforcementStatus) {
        0 { 'Off' }
        1 { 'Audit mode' }
        2 { 'Enforced' }
        Default { "Unknown value ($($dg.CodeIntegrityPolicyEnforcementStatus))" }
    }

    # Build a short comment + recommendation
    $comment = "VBS status: $($dg.VirtualizationBasedSecurityStatus); UMCI (WDAC) status: $($dg.UserModeCodeIntegrityPolicyEnforcementStatus); CI: $cicActive."
    $recommendation = if (-not $vbsActive -and -not $wdacActive) {
        'Consider enabling Virtualization-Based Security (VBS) and Windows Defender Application Control (WDAC) on high-value systems to harden the kernel and control code execution.'
    }
    elseif ($vbsActive -and -not $wdacActive) {
        'VBS is enabled. Evaluate and deploy WDAC / code integrity policies (at least in Audit mode) to control which binaries and scripts can run.'
    }
    elseif ($wdacActive -and $cicActive -eq 'Audit mode') {
        'WDAC / Code Integrity is in Audit mode. Review audit logs and plan to move critical systems to Enforced mode once stable.'
    }
    elseif ($wdacActive -and $cicActive -eq 'Enforced') {
        'WDAC / Code Integrity is enforced. Regularly review and update policies to ensure only trusted code is allowed while minimizing operational impact.'
    }
    else {
        'Review current Device Guard / VBS configuration and align it with your hardening baseline for critical endpoints and servers.'
    }

    [pscustomobject]@{
        VirtualizationBasedSecurityStatus             = $dg.VirtualizationBasedSecurityStatus
        UserModeCodeIntegrityPolicyEnforcementStatus  = $dg.UserModeCodeIntegrityPolicyEnforcementStatus
        CodeIntegrityPolicyEnforcementStatus          = $cicActive
        SecurityServicesConfigured                    = $dg.SecurityServicesConfigured
        SecurityServicesRunning                       = $dg.SecurityServicesRunning
        WDAC_Active                                   = $wdacActive
        VBS_Active                                    = $vbsActive
        Comment                                       = $comment
        Recommendation                                = $recommendation
    }
}
