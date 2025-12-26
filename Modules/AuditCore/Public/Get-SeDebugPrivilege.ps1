function Get-SeDebugPrivilege {
    [CmdletBinding()]
    param ()

    $privilege = 'SeDebugPrivilege'

    # Export local security policy to a temporary file
    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

    $line = $content | Where-Object { $_ -match "^$privilege" }

    if ($line) {
        $sids = ($line -split '=')[1].Trim()
        $sids = ($sids -split ',')

        $isAdminPresent = ($sids -contains '*S-1-5-32-544')  # Builtin Administrators
        $hasExtraSids   = $sids -match 'S-1-' -and -not $sids.Trim().Equals('*S-1-5-32-544')

        $Members = foreach($sid in $sids){if($sid -match "S-*"){$sid = $sid.Substring(1) ; ([wmi]"Win32_SID.SID='$sid'").AccountName}else{$sid}}


        $reco = @()

        if ($isAdminPresent -and -not $hasExtraSids) {
            $reco += 'SeDebugPrivilege is restricted to the built-in Administrators group; review periodically for unwanted additions.'
        }
        elseif ($hasExtraSids) {
            $reco += 'Additional SIDs have SeDebugPrivilege; restrict this right to as few highly trusted admin accounts as possible.'
        }
        else {
            $reco += 'No explicit Administrators SID found for SeDebugPrivilege; verify this is intended and that at least one secure admin group has this right.'
        }

        $DebugState = [PSCustomObject]@{
            Privilege      = $privilege
            Configured     = $true
            AssignedTo  = $Members
            IsAdminPresent = $isAdminPresent
            Recommendation = ($reco -join ' ')
        }
    }
    else {
        $DebugState = [PSCustomObject]@{
            Privilege      = $privilege
            Configured     = $false
            AssignedTo  = $null
            IsAdminPresent = $false
            Recommendation = 'SeDebugPrivilege is not explicitly configured; enforce a policy that restricts this right to a minimal set of admin accounts.'
        }
    }

    return $DebugState
}
