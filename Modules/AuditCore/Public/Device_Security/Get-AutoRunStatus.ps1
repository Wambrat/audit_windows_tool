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
                    $AutoRun.Value          = 'Disabled on all drives (0xFF)'
                    $AutoRun.Comment        = 'Autorun is disabled for all drive types.'
                    $AutoRun.Recommendation = 'Keep Autorun disabled on all drive types to reduce malware propagation risks via removable media.'
                }
                default {
                    $AutoRun.AutoRunEnabled = $true
                    $AutoRun.Value          = ("Current NoDriveTypeAutorun raw value: 0x{0:X2}" -f $value)
                    $AutoRun.Comment        = 'Autorun is not fully disabled for all drive types.'
                    $AutoRun.Recommendation = 'Set NoDriveTypeAutorun to 0xFF via Group Policy or registry to disable Autorun for all drive types.'
                    $Xml = [pscustomobject]@{
                        Category    = 'AutoRun'
                        Description = 'Disable AutoRun in registry for LocalMachine and CurrentUser'
                        Command     = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF | Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Value 0xFF'
                    }
                }
            }

        } else {

            $AutoRun = [pscustomobject]@{
                Scope          = $scope
                AutoRunEnabled = $true
                Value          = 'NoDriveTypeAutorun value not found'
                Comment        = 'No explicit NoDriveTypeAutorun value configured; default Autorun behavior may be partially enabled.'
                Recommendation = 'Explicitly configure NoDriveTypeAutorun (0xFF) to ensure Autorun is disabled for all drive types.'
            }

            $Xml = [pscustomobject]@{
                        Category    = 'AutoRun'
                        Description = 'Disable AutoRun in registry for LocalMachine and CurrentUser'
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
