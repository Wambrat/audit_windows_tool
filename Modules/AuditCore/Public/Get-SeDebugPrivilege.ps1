function Get-SeDebugPrivilege {
    [CmdletBinding()]
    param ()

    $privilege = "SeDebugPrivilege"

    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

    $line = $content | Where-Object { $_ -match "^$privilege" }

    if ($line) {
        $sids = ($line -split "=")[1].Trim()
        $DebugState = [PSCustomObject]@{
            Privilege = $privilege
            Configured = $true
            AssignedTo = $sids
            IsAdminPresent = ($sids -match "S-1-5-32-544")
        }
    } else {
        $DebugState = [PSCustomObject]@{
            Privilege = $privilege
            Configured = $false
            AssignedTo = $null
            IsAdminPresent = $false
        }
    }

    Return $DebugState

}
