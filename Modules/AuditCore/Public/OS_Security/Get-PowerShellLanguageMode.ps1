function Get-PowerShellLanguageMode {
    [CmdletBinding()]
    param()

    $mode = $ExecutionContext.SessionState.LanguageMode

    $isConstrained = ($mode -eq 'ConstrainedLanguage')

    # Simple recommendation based on language mode
    $recommendation = if ($isConstrained) {
        "PowerShell s'execute en mode ConstrainedLanguage ; verifiez que cela est applique via AppLocker/WDAC dans le cadre de votre base de durcissement et que les scripts d'administration requis fonctionnent toujours."
    }
    else {
        "PowerShell s'execute en mode FullLanguage (ou moins restreint) ; envisagez d'appliquer ConstrainedLanguage aux utilisateurs standard via AppLocker/WDAC pour une meilleure resistance aux abus."
    }

    [pscustomobject]@{
        LanguageMode  = $mode
        IsConstrained = $isConstrained
        Recommendation = $recommendation
    }
}

