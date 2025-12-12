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
            [pscustomobject]@{
                Scope        = $scope
                RegistryPath = $path
                SRPPresent   = $false
                Comment      = 'Aucune SRP détectée sur ce scope.'
            }
            continue
        }

        $rulesKey = Join-Path $path '0\Paths'
        $hasRules = Test-Path $rulesKey

        $comment = if ($hasRules) {
            'SRP detected: recommended to replace with AppLocker or WDAC depending on the policy.'
        } else {
            'SRP key present but without Paths rules'
        }

        $SRP = [pscustomobject]@{
            Scope        = $scope
            RegistryPath = $path
            SRPPresent   = $hasRules
            Comment      = $comment
        }

        [void]$Print.add($SRP)

    }

    return $Print
}
