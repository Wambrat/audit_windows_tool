function Get-PowerShellLanguageMode {
    [CmdletBinding()]
    param()

    $mode = $ExecutionContext.SessionState.LanguageMode

    $isConstrained = ($mode -eq 'ConstrainedLanguage')

    # Simple recommendation based on language mode
    $recommendation = if ($isConstrained) {
        'PowerShell is running in ConstrainedLanguage mode; verify this is enforced via AppLocker/WDAC as part of your hardening baseline and that required admin scripts still work.'
    }
    else {
        'PowerShell is running in FullLanguage (or less restricted) mode; consider enforcing ConstrainedLanguage on standard users via AppLocker/WDAC for better abuse resistance.'
    }

    [pscustomobject]@{
        LanguageMode  = $mode
        IsConstrained = $isConstrained
        Recommendation = $recommendation
    }
}
