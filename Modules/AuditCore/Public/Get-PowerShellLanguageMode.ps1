function Get-PowerShellLanguageMode {
    [CmdletBinding()]
    param()

    $mode = $ExecutionContext.SessionState.LanguageMode

    $LanguageMode = [pscustomobject]@{
        LanguageMode = $mode
        IsConstrained = ($mode -eq 'ConstrainedLanguage')
    }

    Return $LanguageMode
}
