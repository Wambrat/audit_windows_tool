function Get-AutorunStatus {
    [CmdletBinding()]
    param()

    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    $Print = [System.Collections.ArrayList]@()

    foreach ($path in $paths) {

        $keys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        $scope = if ($path -like 'HKLM:*') { 'Machine' } else { 'User' }

        if ($keys -and $keys.PSObject.Properties.Name -contains 'NoDriveTypeAutorun') {

            $value = [int]$keys.NoDriveTypeAutorun

            $AutoRun = [pscustomobject]@{
                Scope          = $scope
                AutoRunEnabled = $null
                Value          = $null
                Comment        = $null
                Recommendation = $null
            }

            switch ($value) {
                0xFF {
                    $AutoRun.AutoRunEnabled = $false
                    $AutoRun.Value          = 'Desactiver sur tous les types de lecteurs (0xFF)'
                    $AutoRun.Comment        = 'AutoRun est desactive pour tous les types de lecteurs.'
                    $AutoRun.Recommendation = 'Gardez AutoRun desactive sur tous les types de lecteurs pour reduire les risques de propagation de malwares via les medias amovibles.'
                }
                default {
                    $AutoRun.AutoRunEnabled = $true
                    $AutoRun.Value          = ("La valeur brute actuelle de NoDriveTypeAutorun : 0x{0:X2}" -f $value)
                    $AutoRun.Comment        = "AutoRun n'est pas entierement desactive pour tous les types de lecteurs."
                    $AutoRun.Recommendation = 'Definissez NoDriveTypeAutorun a 0xFF via Group Policy ou le registre pour desactiver AutoRun pour tous les types de lecteurs.'
                    $Xml = [pscustomobject]@{
                        Category    = 'AutoRun'
                        Description = "Desactivation d'AutoRun dans le registre pour LocalMachine et CurrentUser"
                        Command     = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF | Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF'
                    }
                }
            }

        } else {

            $AutoRun = [pscustomobject]@{
                Scope          = $scope
                AutoRunEnabled = $true
                Value          = 'La valeur NoDriveTypeAutorun est introuvable'
                Comment        = "Pas de valeur NoDriveTypeAutorun explicite configuree; le comportement par defaut d'AutoRun peut etre partiellement active."
                Recommendation = "Configurez explicitement NoDriveTypeAutorun (0xFF) pour vous assurer qu'AutoRun est desactive pour tous les types de lecteurs.'"
            }

            $Xml = [pscustomobject]@{
                        Category    = 'AutoRun'
                        Description = "Desactivez AutoRun dans le registre pour LocalMachine et CurrentUser"
                        Command     = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF | Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF'
            }
        }

        [void]$Print.Add($AutoRun)
    }

    $Output = [PSCustomObject]@{
        Value = $Print
        Xml = $Xml
    }
    
    return $Output
}

