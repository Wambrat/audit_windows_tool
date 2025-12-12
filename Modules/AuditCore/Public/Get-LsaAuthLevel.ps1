function Get-LsaAuthLevel {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $val  = (Get-ItemProperty -Path $path -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel

    $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption


    switch ($val) {
        0 {$desc = 'Send LM and NTLM replies'}
        1 {$desc = 'Send LM and NTLM, NTLMv2 if negotiated'}
        2 {$desc = 'Send only NTLM'}
        3 {$desc = 'Send only NTLMv2'}
        4 {$desc = 'Reject LM, send NTLM & NTLMv2'}
        5 {$desc = 'Send NTLMv2 only, reject LM and NTLM'}
        default {$desc = 'Key not found / Default value applied'}
    }

    $reco =
        if ($os -match 'Server') {

            if ($val -ge 5) { 'OK: High level, LM/NTLM rejected.' }
            else { 'Recommended (server): LmCompatibilityLevel=5 (NTLMv2 only, refuses LM & NTLM).' }
        }
        else {

            if ($val -ge 3) { 'OK: NTLMv2 only (or stricter).' }
            else { 'Recommended (client): LmCompatibilityLevel≥3 (NTLMv2 only).' }
        }

    $State = [pscustomobject]@{
        Path            = $path
        LmCompatibilityLevel = if($val){$val}else{"N/A"}
        Description     = $desc
        Recommendation  = $reco
    }

    Return $State
}
