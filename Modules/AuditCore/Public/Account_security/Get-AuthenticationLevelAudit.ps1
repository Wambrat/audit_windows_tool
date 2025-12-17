
function Get-AuthenticationLevelAudit {
    [CmdletBinding()]
    param()

    process{
        # Initialisation du tableau des méthodes activées
        $ActivatedMethods = @(
            GPO = $false
            CSP = $false
        )

        # Vérification des configurations Windows Hello for Business via GPO
        $whfb = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($whfb.value -eq 1) {
            Write-Host "Windows Hello for Business est activé via GPO."
            $ActivatedMethods.GPO = $true
        } else {
            Write-Host "Windows Hello for Business n'est pas activé par GPO."
        }

        # Vérification des configurations Windows Hello for Business via CSP
        $whfb = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork" -Name "UsePassportForWork" -ErrorAction SilentlyContinue
        if ($whfb.value -eq 1) {
            Write-Host "Windows Hello for Business est activé via CSP."
            $ActivatedMethods.CSP = $true
        } else {
            Write-Host "Windows Hello for Business n'est pas activé par CSP."
        }  

        return [PSCustomObject]@{
            GPO = $ActivatedMethods.GPO
            CSP = $ActivatedMethods.CSP
        }
    }
}