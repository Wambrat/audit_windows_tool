function Get-UACAudit{
    [CmdletBinding()]
    param()

    $XmlList = [System.Collections.ArrayList]@()

    $result = [pscustomobject]@{
        EnableLUA                   = $null   # UAC global on/off (0/1)
        ConsentPromptAdmin          = $null   # ConsentPromptBehaviorAdmin
        ConsentPromptUser           = $null   # ConsentPromptBehaviorUser
        PromptOnSecureDesktop       = $null   # PromptOnSecureDesktop
        FilterAdministratorTokenRaw = $null   # raw DWORD
        LocalAccountTokenFilterRaw  = $null   # raw DWORD
        InteractiveLogonFirstRaw    = $null   # raw DWORD
        EnableUIADesktopToggle      = $null
        EnableInstallerDetection    = $null
        ValidateAdminCodeSignatures = $null
        EnableSecureUIAPaths        = $null
        EnableVirtualization        = $null

        LocalAccountTokenFilter     = $null   # human readable
        FilterAdministratorToken    = $null
        InteractiveLogonFirst       = $null
        Recommendation              = $null
    }

    $uacReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

    if (-not $uacReg) {
        $result.Recommendation = 'UAC policy keys not found; ensure User Account Control is enabled and configured via GPO according to your hardening baseline.'
        return $result
    }

    # Raw values
    $result.EnableLUA                   = $uacReg.EnableLUA
    $result.ConsentPromptAdmin          = $uacReg.ConsentPromptBehaviorAdmin
    $result.ConsentPromptUser           = $uacReg.ConsentPromptBehaviorUser
    $result.PromptOnSecureDesktop       = $uacReg.PromptOnSecureDesktop
    $result.FilterAdministratorTokenRaw = $uacReg.FilterAdministratorToken
    $result.LocalAccountTokenFilterRaw  = $uacReg.LocalAccountTokenFilterPolicy
    $result.InteractiveLogonFirstRaw    = $uacReg.InteractiveLogonFirst
    $result.EnableUIADesktopToggle      = $uacReg.EnableUIADesktopToggle
    $result.EnableInstallerDetection    = $uacReg.EnableInstallerDetection
    $result.ValidateAdminCodeSignatures = $uacReg.ValidateAdminCodeSignatures
    $result.EnableSecureUIAPaths        = $uacReg.EnableSecureUIAPaths
    $result.EnableVirtualization        = $uacReg.EnableVirtualization

    # LocalAccountTokenFilterPolicy (UAC restrictions on local admins over network)
    switch ($uacReg.LocalAccountTokenFilterPolicy) {
        1     { $result.LocalAccountTokenFilter = 'Enabled (recommended for restricting local admin tokens over network)' }
        0     { $result.LocalAccountTokenFilter = 'Disabled (local admins receive elevated tokens over network)' }
        $null { $result.LocalAccountTokenFilter = 'Key not found (default behavior applies)' }
        default { $result.LocalAccountTokenFilter = "Unknown value ($($uacReg.LocalAccountTokenFilterPolicy))" }
    }

    # FilterAdministratorToken (built-in Administrator in Admin Approval Mode)
    switch ($uacReg.FilterAdministratorToken) {
        1     { $result.FilterAdministratorToken = 'Enabled (built-in Administrator uses Admin Approval Mode)' }
        0     { $result.FilterAdministratorToken = 'Disabled (built-in Administrator not in Admin Approval Mode)' }
        $null { $result.FilterAdministratorToken = 'Key not found (default: disabled)' }
        default { $result.FilterAdministratorToken = "Unknown value ($($uacReg.FilterAdministratorToken))" }
    }

    # InteractiveLogonFirst (prioritize network logons over cached logons)
    switch ($uacReg.InteractiveLogonFirst) {
        1     { $result.InteractiveLogonFirst = 'Enabled (prioritize domain/network logons)' }
        0     { $result.InteractiveLogonFirst = 'Disabled (default behavior)' }
        $null { $result.InteractiveLogonFirst = 'Key not found (default behavior)' }
        default { $result.InteractiveLogonFirst = "Unknown value ($($uacReg.InteractiveLogonFirst))" }
    }

    # High-level recommendation
    $reco = @()

    if ($result.EnableLUA -ne 1) {
        $reco += 'Enable UAC globally (EnableLUA = 1) to ensure elevation prompts and token splitting are enforced.'
        $Xml = [pscustomobject]@{
                Category    = "UAC - Enable LUA"
                Description = "Enable UAC globally (EnableLUA = 1) to ensure elevation prompts and token splitting are enforced."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"
            }
        [void]$XmlList.Add($xml)
    }

    if ($uacReg.PromptOnSecureDesktop -ne 1) {
        $reco += 'Enable secure desktop for elevation prompts (PromptOnSecureDesktop = 1) to reduce spoofing risks.'
        $Xml = [pscustomobject]@{
                Category    = "UAC - Secure Desktop"
                Description = "Enable secure desktop for elevation prompts (PromptOnSecureDesktop = 1) to reduce spoofing risks."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1"
            }
        [void]$XmlList.Add($xml)
    }

    if ($uacReg.ConsentPromptBehaviorAdmin -eq 0 -or $uacReg.ConsentPromptBehaviorAdmin -eq 4) {
        $reco += 'Tighten admin elevation prompts (ConsentPromptBehaviorAdmin) to require at least consent on the secure desktop for non-Windows binaries.'
        $Xml = [pscustomobject]@{
                Category    = "UAC - Consent Prompt Behavior Admin"
                Description = "Tighten admin elevation prompts (ConsentPromptBehaviorAdmin) to require at least consent on the secure desktop for non-Windows binaries."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5"
            }
        [void]$XmlList.Add($xml)
    }

    if ($uacReg.LocalAccountTokenFilterPolicy -ne 1) {
        $reco += 'Set LocalAccountTokenFilterPolicy = 1 to restrict local administrator tokens over network connections.'
        $Xml = [pscustomobject]@{
                Category    = "UAC - Local Account Token Filter Policy"
                Description = "Set LocalAccountTokenFilterPolicy = 1 to restrict local administrator tokens over network connections."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1"
            }
        [void]$XmlList.Add($xml)
    }

    if ($uacReg.FilterAdministratorToken -ne 1) {
        $reco += 'Enable FilterAdministratorToken = 1 so the built-in Administrator account also uses Admin Approval Mode.'
        $Xml = [pscustomobject]@{
                Category    = "UAC - Filter Administrator Token"
                Description = "Enable FilterAdministratorToken = 1 so the built-in Administrator account also uses Admin Approval Mode."
                Command     = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Value 1"
            }
        [void]$XmlList.Add($xml)
    }

    $result.Recommendation = if ($reco.Count -gt 0) {
        $reco -join ' '
    }
    else {
        'UAC configuration appears aligned with common hardening baselines; review exception cases and remote administration scenarios.'
    }

    return [PSCustomObject]@{
        Value = $result
        Xml = $XmlList
    }
}
    


