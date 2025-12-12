function Get-JEAAudit {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        WinRmState           = $null
        HasJEASessionConfig  = $false
        SessionConfigurations= @()
        RoleCapabilityFiles  = @()
        PSModulePaths        = $null
    }

    $WinRM = Get-service winrm

    if($WinRM.Status -eq "Running"){

        $sessionConfigs = Get-PSSessionConfiguration -ErrorAction SilentlyContinue | Select-Object Name, Permission


        if ($sessionConfigs) {
            $result.HasJEASessionConfig   = $true
            $result.SessionConfigurations = $sessionConfigs
        }

        $psModulePath = $env:PSModulePath -split ';'

        $result.PSModulePaths = $psModulePath

        $files = @()
        foreach ($p in $psModulePath) {
                if (Test-Path $p) {
                    $files += Get-ChildItem -Path $p -Recurse -Filter *.psrc -ErrorAction SilentlyContinue
                }
        }

        if ($files) {
            $result.RoleCapabilityFiles = $files.Name
        }
    
    }else{
        
        $result.WinRmState = $WinRM.Status
        $result.HasJEASessionConfig = "N/A"
        $result.SessionConfigurations = "N/A" 
        $result.RoleCapabilityFiles = "N/A"
        $result.PSModulePaths = "N/A"

    }

    Return $result

}
