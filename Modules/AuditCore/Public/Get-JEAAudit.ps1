function Get-JEAAudit {
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        WinRmState            = $null
        HasJEASessionConfig   = $false
        SessionConfigurations = @()
        RoleCapabilityFiles   = @()
        PSModulePaths         = @()
        Comment               = $null
        Recommendation        = $null
    }

    $winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

    if (-not $winrm) {
        $result.WinRmState     = 'NotInstalled'
        $result.Comment        = 'WinRM service is not installed or not accessible on this host.'
        $result.Recommendation = 'If JEA / PowerShell remoting is required, install and configure WinRM securely (HTTPS, restricted endpoints, JEA).'
        return $result
    }

    $result.WinRmState = $winrm.Status.ToString()

    if ($winrm.Status -ne 'Running') {
        $result.Comment        = 'WinRM service is present but not running; JEA endpoints will not be usable.'
        $result.Recommendation = 'Start and secure WinRM only on systems where remote administration and JEA are required.'
        return $result
    }

    $sessionConfigs = Get-PSSessionConfiguration -ErrorAction SilentlyContinue |
                      Select-Object Name, Permission

    if ($sessionConfigs) {
        $result.HasJEASessionConfig   = $true
        $result.SessionConfigurations = $sessionConfigs
        $result.Comment               = 'One or more PowerShell session configurations are registered; some may be JEA endpoints.'
        $result.Recommendation        = 'Review JEA session configurations to ensure they expose only the minimum required cmdlets and are restricted to appropriate groups.'
    }
    else {
        $result.HasJEASessionConfig   = $false
        $result.Comment               = 'No custom PowerShell session configuration found; JEA does not appear to be configured.'
        $result.Recommendation        = 'Consider deploying JEA endpoints for privileged tasks instead of granting full admin remoting access.'
    }

    $psModulePath = $env:PSModulePath -split ';'
    $result.PSModulePaths = $psModulePath

    $files = @()
    foreach ($p in $psModulePath) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (Test-Path -LiteralPath $p) {
            $files += Get-ChildItem -Path $p -Recurse -Filter '*.psrc' -ErrorAction SilentlyContinue
        }
    }

    if ($files) {
        $result.RoleCapabilityFiles = $files.FullName
    }

    return $result
}
