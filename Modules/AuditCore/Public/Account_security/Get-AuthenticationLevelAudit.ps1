
function Get-AuthenticationLevelAudit {
    [CmdletBinding()]
    param()

    process{
        # Initialisation du tableau des methodes activees
        $ActivatedMethods = [PSCustomObject]@{
            GPO = $false
            CSP = $false
            Consumer = $false
        }

        # Verification des configurations Windows Hello for Business via GPO
        $whfb = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($whfb.value -eq 1) {
            $ActivatedMethods.GPO = $true
        }

        # Verification des configurations Windows Hello for Business via CSP
        $whfb = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork" -Name "UsePassportForWork" -ErrorAction SilentlyContinue
        if ($whfb.value -eq 1) {
            $ActivatedMethods.CSP = $true
        }

        # Verification des configurations Windows Hello Consumer
        $ngcPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Ngc"
        if (Test-Path $ngcPath) {
            $ngcKey = Get-Item -Path $ngcPath
            
            $enrolledUsers = $ngcKey.GetSubKeyNames()
            
            if ($enrolledUsers.Count -gt 0) {
                $ActivatedMethods.Consumer = $true
            }
        } else {
            Write-Host "Le service Ngc (Windows Hello) ne semble pas present."
        }

        return $ActivatedMethods
        
    }
}
