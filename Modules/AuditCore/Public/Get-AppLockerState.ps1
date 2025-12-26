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
            Comment          = 'No effective AppLocker policy detected on this system.'
            Recommendation   = 'Consider deploying an AppLocker policy (at least in Audit mode) to control application execution.'
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

    [pscustomobject]@{
        AppLockerPresent = $true
        AnyRuleEnabled   = $anyEnabled
        Comment          = if ($anyEnabled) {
                               'AppLocker is present and at least one rule collection is in Enforced mode.'
                           } else {
                               'AppLocker is present but no rule collection is in Enforced mode.'
                           }
        Recommendation   = if ($anyEnabled) {
                               'Review AppLocker rules regularly to ensure they properly cover sensitive applications and are kept up to date.'
                           } else {
                               'Enable AppLocker in Audit mode first, then gradually switch required rule collections to Enforced mode to block unauthorized applications.'
                           }
    }
}
