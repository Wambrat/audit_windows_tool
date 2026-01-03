function Get-SRPState {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers',
        'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
    )

    foreach ($path in $paths) {
        $scope = if ($path -like 'HKLM*') { 'Machine' } else { 'User' }

        if (-not (Test-Path $path)) {
            $obj = [pscustomobject]@{
                Scope        = $scope
                RegistryPath = $path
                SRPPresent   = $false
                Comment      = 'No Software Restriction Policy (SRP) detected for this scope.'
                Recommendation = 'Prefer AppLocker or Windows Defender Application Control (WDAC) instead of legacy SRP for application control.'
            }
            [void]$Print.Add($obj)
            continue
        }

        $rulesKey = Join-Path $path '0\Paths'
        $hasRules = Test-Path $rulesKey

        $comment = if ($hasRules) {
            'Software Restriction Policies (SRP) are defined for this scope.'
        } else {
            'SRP root key exists but no Path rules were found.'
        }

        $reco = if ($hasRules) {
            'Plan to migrate from legacy SRP to AppLocker or WDAC for stronger and more flexible application control.'
        } else {
            'If SRP is not actively used, consider cleaning up legacy keys and implementing AppLocker or WDAC instead.'
        }

        $SRP = [pscustomobject]@{
            Scope          = $scope
            RegistryPath   = $path
            SRPPresent     = $hasRules
            Comment        = $comment
            Recommendation = $reco
        }

        [void]$Print.Add($SRP)
    }

    return $Print
}
