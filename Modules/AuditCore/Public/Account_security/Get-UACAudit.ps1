function Get-UACAudit {
    [CmdletBinding()]
    param()

    process{

        $uacRegParent = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
        $uacRegFAT = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -ErrorAction SilentlyContinue
        $uacRegLATFP = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

        $UACResult = [PSCustomObject]@{
            UACEnabled                          = $null   # UAC global on/off (0/1)
            FilterAdministratorToken            = $null   # FilterAdministratorToken
            LocalAccountTokenFilterPolicy       = $null   # LocalAccountTokenFilterPolicy
        }

        if (-not $uacRegParent) {
            return $UACResult
        }

        if ($uacRegFAT.value -eq 1) {
            $UACResult.FilterAdministratorToken = 1
        }
        
        if ($uacRegLATFP.value -eq 1) {
            $UACResult.LocalAccountTokenFilterPolicy = 1
        }

        return $UACResult
    }
}
