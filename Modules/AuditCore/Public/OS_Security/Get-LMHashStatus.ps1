function Get-LMHashStatus {
    [CmdletBinding()]
    param()

    $path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $value = (Get-ItemProperty -Path $path -Name 'NoLMHash' -ErrorAction SilentlyContinue).NoLMHash

    $enabled = ($value -eq 1)

    if ($null -eq $value) {
        $desc = 'NoLMHash value not found; LM hashes may still be stored depending on system defaults.'
        $reco = 'Explicitly set NoLMHash = 1 via security policy/GPO and force a password change for all local/domain accounts.'
        $Xml = [pscustomobject]@{
                Category    = 'LM Hash'
                Description = 'Disable storing of LM Hash in registry'
                Command     = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1'
        }
    }
    elseif ($enabled) {
        $desc = 'LM hashes are not stored (NoLMHash = 1).'
        $reco = 'Keep NoLMHash = 1 and ensure password length and complexity are aligned with your security baseline.'
    }
    else {
        $desc = 'LM hashes may be stored (NoLMHash != 1).'
        $reco = 'Set NoLMHash = 1 and force a password change for all accounts to remove existing LM hashes.'
        $Xml = [pscustomobject]@{
                Category    = 'LM Hash'
                Description = 'Disable storing of LM Hash in registry'
                Command     = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1'
        }
    }

    $LMHash = [pscustomobject]@{
        Path         = $path
        NoLMHash     = if ($null -ne $value) { $value } else { 'N/A' }
        LMStored     = -not $enabled
        Description  = $desc
        Recommendation = $reco
    }

    $Output = [PSCustomObject]@{
        Value = $LMHash
        Xml = $Xml
    }

    Return $Output
}
