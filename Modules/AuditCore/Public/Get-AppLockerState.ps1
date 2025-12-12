function Get-AppLockerState {
    [CmdletBinding()]
    param()

    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            AppLockerPresent = $false
            AnyRuleEnabled   = $false
            Comment          = 'Aucune politique AppLocker effective détectée.'
        }
    }

    $collections = @('Exe','Script','Msi','Dll','Appx')
    $anyEnabled  = $false

    foreach ($c in $collections) {
        $col = $policy.RuleCollections | Where-Object { $_.CollectionType -eq $c }
        if ($col -and $col.EnforcementMode -eq 'Enabled') {
            $anyEnabled = $true
            break
        }
    }

    $ALS = [pscustomobject]@{
        AppLockerPresent = $true
        AnyRuleEnabled   = $anyEnabled
        Comment          = if ($anyEnabled) {
                               'AppLocker present and at least one collection in Enabled mode'
                           } else {
                               'AppLocker present but no collection in Enabled mode'
                           }
    }

    Return $ALS

}
