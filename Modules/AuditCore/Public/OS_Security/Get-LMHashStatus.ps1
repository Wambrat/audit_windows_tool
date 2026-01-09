function Get-LMHashStatus {
    [CmdletBinding()]
    param()

    $path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $value = (Get-ItemProperty -Path $path -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash

    $enabled = ($value -eq 1)

    if ($null -eq $value) {
        $desc = "Valeur NoLMHash introuvable; Les hachages LM peuvent toujours etre stockes en fonction des paramètres par defaut du système."
        $reco = "Definissez explicitement NoLMHash = 1 via la politique de securite/GPO et forcez un changement de mot de passe pour tous les comptes locaux/de domaine."
        $Xml = [pscustomobject]@{
                Category    = "LM Hash"
                Description = "Desactiver le stockage de LM Hash dans le registre"
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1"
        }
    }
    elseif ($enabled) {
        $desc = "Les hachages LM ne sont pas stockes (NoLMHash = 1)."
        $reco = "Gardez NoLMHash = 1 et assurez-vous que la longueur et la complexite du mot de passe sont alignees sur votre base de securite."
    }
    else {
        $desc = "Les hachages LM peuvent etre stockes (NoLMHash != 1)."
        $reco = "Definissez NoLMHash = 1 et forcez un changement de mot de passe pour tous les comptes afin de supprimer les hachages LM existants."
        $Xml = [pscustomobject]@{
                Category    = "LM Hash"
                Description = "Desactiver le stockage de LM Hash dans le registre"
                Command     = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1"
        }
    }

    $LMHash = [pscustomobject]@{
        Path         = $path
        NoLMHash     = if ($null -ne $value) { $value } else { "N/A" }
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

