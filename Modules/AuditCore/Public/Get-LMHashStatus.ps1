function Get-LMHashStatus {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $value  = (Get-ItemProperty -Path $path -Name 'NoLMHash' -ErrorAction SilentlyContinue).NoLMHash

    $enabled = ($val -eq 1)
    $desc    = if ($enabled) {
        'OK: LM not stored (NoLMHash=1).'
    } else {
        'Recommended: enable NoLMHash=1 and force a password change.'
    }

    $State = [pscustomobject]@{
        Path        = $path
        NoLMHash    = $val
        LMStored    = -not $enabled
        Description = $desc
    }

    Return $State
}
