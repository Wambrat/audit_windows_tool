function Get-UACAudit {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        EnableLUA                 = $null   # UAC global on/off
        ConsentPromptAdmin        = $null   # ConsentPromptBehaviorAdmin
        ConsentPromptUser         = $null   # ConsentPromptBehaviorUser
        PromptOnSecureDesktop     = $null   # PromptOnSecureDesktop
        FilterAdministratorToken  = $null   # Reco: 1
        LocalAccountTokenFilter   = $null   # Reco: 1
        EnableUIADesktopToggle    = $null
        EnableInstallerDetection  = $null
        ValidateAdminCodeSignatures = $null
        EnableSecureUIAPaths = $null
        EnableVirtualization = $null
        InteractiveLogonFirst = $null
    }

    # Clé principale UAC
    $uacReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue

    if ($uacReg) {
        $result.EnableLUA             = $uacReg.EnableLUA
        $result.ConsentPromptAdmin    = $uacReg.ConsentPromptBehaviorAdmin
        $result.ConsentPromptUser     = $uacReg.ConsentPromptBehaviorUser
        $result.PromptOnSecureDesktop = $uacReg.PromptOnSecureDesktop
        $result.FilterAdministratorToken = $uacReg.FilterAdministratorToken
        $result.EnableUIADesktopToggle = $uacReg.EnableUIADesktopToggle
        $result.EnableInstallerDetection = $uacReg.EnableInstallerDetection
        $result.ValidateAdminCodeSignatures = $uacReg.ValidateAdminCodeSignatures
        $result.EnableSecureUIAPaths = $uacReg.EnableSecureUIAPaths
        $result.EnableVirtualization = $uacReg.EnableVirtualization
    }

    switch($uacReg.LocalAccountTokenFilterPolicy){

        1{$result.LocalAccountTokenFilter = "Enabled"}
        0{$result.LocalAccountTokenFilter = "Disabled"}
        $null{$result.LocalAccountTokenFilter = "Key not found"}
        Default{$result.LocalAccountTokenFilter = "Unknown Value"}

    }

    switch($uacReg.FilterAdministratorToken){
        
        1{$result.FilterAdministratorToken = "Enabled"}
        0{$result.FilterAdministratorToken = "Disabled"}
        $null{$result.FilterAdministratorToken = "Key not found"}
        Default{$result.FilterAdministratorToken = "Unknown Value"}

    }

    switch($uacReg.InteractiveLogonFirst){

        1{$result.InteractiveLogonFirst = "Enabled"}
        0{$result.InteractiveLogonFirst = "Disabled"}
        $null{$result.InteractiveLogonFirst = "Key not found"}
        Default{$result.InteractiveLogonFirst = "Unknown Value"}

    }

    Return $result
}
