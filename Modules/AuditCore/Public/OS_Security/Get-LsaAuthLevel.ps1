function Get-LsaAuthLevel {
    [CmdletBinding()]
    param()

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $val  = (Get-ItemProperty -Path $path -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel

    $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

    switch ($val) {
        0      { $desc = "Envoyez les reponses LM et NTLM." }
        1      { $desc = "Envoyer des reponses LM et NTLM; utilisez la securite de session NTLMv2 si elle est negociee." }
        2      { $desc = "Envoyez uniquement des reponses NTLM." }
        3      { $desc = "Envoyez uniquement des reponses NTLMv2." }
        4      { $desc = "Controleurs de domaine : refuser LM ; clients : envoyer NTLM et NTLMv2." }
        5      { $desc = "Envoyez uniquement des reponses NTLMv2; refuser LM et NTLM." }
        $null  { $desc = "Cle introuvable; le système utilise LmCompatibilityLevel par defaut." }
        default{ $desc = "Valeur LmCompatibilityLevel inconnue ($val)." }
    }

    # Recommendation depending on OS type and effective value
    if ($os -match "Server") {
        if ($val -ge 5) {
            $reco = "OK : Niveau de compatibilite eleve pour les serveurs ; LM et NTLM sont rejetes (NTLMv2 uniquement)."
        }
        else {
            $reco = "Recommande (serveur) : definissez LmCompatibilityLevel = 5 pour autoriser uniquement NTLMv2 et refuser LM et NTLM."
            $Xml = [pscustomobject]@{
                Category    = "LsaAuthLevel"
                Description = "Envoyez uniquement des reponses NTLMv2; refuser LM et NTLM"
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5"
            }
        }
    }
    else {
        if ($val -ge 3) {
            $reco = "OK: le client est configure pour NTLMv2 uniquement (ou plus strict)."
        }
        else {
            $reco = "Recommande (client/poste de travail) : definissez LmCompatibilityLevel sur au moins 3 (NTLMv2 uniquement)."
            $Xml = [pscustomobject]@{
                Category    = "LsaAuthLevel"
                Description = "Envoyer uniquement les reponses NTLMv2"
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 3"
            }
        }
    }

    $LsaAuthLevel = [pscustomobject]@{
        Path                 = $path
        LmCompatibilityLevel = if ($val) { $val } else { "N/A" }
        Description          = $desc
        Recommendation       = $reco
    }

    $Output = [PSCustomObject]@{
        Value = $LsaAuthLevel
        Xml = $Xml
    }

    Return $Output
}

