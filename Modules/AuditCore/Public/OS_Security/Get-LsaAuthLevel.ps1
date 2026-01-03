function Get-LsaAuthLevel {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $val  = (Get-ItemProperty -Path $path -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel

    $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

    switch ($val) {
        0      { $desc = 'Send LM and NTLM responses.' }
        1      { $desc = 'Send LM and NTLM responses; use NTLMv2 session security if negotiated.' }
        2      { $desc = 'Send only NTLM responses.' }
        3      { $desc = 'Send NTLMv2 responses only.' }
        4      { $desc = 'Domain controllers: refuse LM; clients: send NTLM and NTLMv2.' }
        5      { $desc = 'Send NTLMv2 responses only; refuse LM and NTLM.' }
        $null  { $desc = 'Key not found; system is using default LmCompatibilityLevel.' }
        default{ $desc = "Unknown LmCompatibilityLevel value ($val)." }
    }

    # Recommendation depending on OS type and effective value
    if ($os -match 'Server') {
        if ($val -ge 5) {
            $reco = 'OK: High compatibility level for servers; LM and NTLM are rejected (NTLMv2 only).'
        }
        else {
            $reco = 'Recommended (server): set LmCompatibilityLevel = 5 to allow only NTLMv2 and refuse LM and NTLM.'
            $Xml = [pscustomobject]@{
                Category    = 'LsaAuthLevel'
                Description = 'Send NTLMv2 responses only; refuse LM and NTLM'
                Command     = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5'
            }
        }
    }
    else {
        if ($val -ge 3) {
            $reco = 'OK: Client is configured for NTLMv2-only (or stricter).'
        }
        else {
            $reco = 'Recommended (client/workstation): set LmCompatibilityLevel to at least 3 (NTLMv2-only).'
            $Xml = [pscustomobject]@{
                Category    = 'LsaAuthLevel'
                Description = 'Send NTLMv2 responses only'
                Command     = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 3'
            }
        }
    }

    $LsaAuthLevel = [pscustomobject]@{
        Path                 = $path
        LmCompatibilityLevel = if ($val -ne $null) { $val } else { 'N/A' }
        Description          = $desc
        Recommendation       = $reco
    }

    $Output = [PSCustomObject]@{
        Value = $LsaAuthLevel
        Xml = $Xml
    }

    Return $Output
}
