function Get-AutorunStatus {
    [CmdletBinding()]
    param()

    

    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    $Print = [System.Collections.ArrayList]@()

    foreach($path in $paths){
        
        $keys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue

        $scope = if ($path -like 'HKLM:*') { 'Machine' } else { 'User' } 

        if($keys.PSObject.Properties.Name -contains "NoDriveTypeAutorun"){
            
            $AutoRun = [pscustomobject]@{
                Scope = $scope
                AutoRunEnabled = $false          
                Value = $null         
            }

            switch($keys.NoDriveTypeAutorun){
                
                "FF"{$AutoRun.Value = "Disable on all drives"}
                "20"{$AutoRun.Value = "Disable on DC-ROM drives"}
                "4" {$AutoRun.Value = "Disable on removable drives"}
                "8" {$AutoRun.Value = "Disable on fixed drives"}
                "10"{$AutoRun.Value = "Disable on network drives"}
                "40"{$AutoRun.Value = "Disable on RAM disks"}
                "1" {$AutoRun.Value = "Disable on unknown drives"}
                Default { $AutoRun.AutoRunEnabled = "Unknown state (potentially activated)"
                          $AutoRun.Value = "Invalid value"
                }


            }

        }else{

            $AutoRun = [pscustomobject]@{
                Scope = $scope
                AutoRunEnabled = $true
                Value = "Key not found"             
            }

        }

        [void]$Print.Add($AutoRun)

    }

    return $Print

}
