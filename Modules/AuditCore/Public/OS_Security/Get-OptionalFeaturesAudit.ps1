function Get-OptionalFeaturesAudit {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $features = Get-WindowsOptionalFeature -Online |
                Where-Object State -eq 'Enabled' |
                Sort-Object FeatureName

    foreach ($f in $features) {

        $risk = switch -Wildcard ($f.FeatureName) {
            'IIS*'         { "Potentiellement un service web expose (IIS) ; augmente la surface d'attaque s'il est expose a Internet." }
            'TelnetClient' { "Protocol obsolete et non securise (Telnet envoie les informations d'identification en texte clair)." }
            'SMB1Protocol' { "Protocole de partage de fichiers hereditee et vulnerable (SMBv1) ; doit etre supprime." }
            'TFTPClient'   { "Protocole de transfert de fichiers non securise (TFTP) sans authentification ni chiffrement." }
            'FTP*'         { "Transfert de fichiers non chiffre; devrait être restreint ou remplace par SFTP/FTPS." }
            'Hyper-V*'     { "Role de virtualisation; ne gardez que sur des hotes dedies a la virtualisation ou dans des laboratoires." }
            'WCF-*HTTP*'   { "Composants WCF exposes via HTTP ; verifiez qu'ils sont necessaires et correctement durcis."}
            Default        { '' }
        }

        $reco = if ($risk) {
            "Supprimez ou desactivez cette fonctionnalite si elle n'est pas strictement requise, et assurez-vous qu'elle n'est pas exposee a des reseaux non fiables."
        }
        else {
            "Revoir si cette fonctionnalite optionnelle est reellement utilisee ; la desactiver si elle n'est pas necessaire pour reduire la surface d'attaque."
        }

        $OFA = [pscustomobject]@{
            FeatureName    = $f.FeatureName
            State          = $f.State
            RiskNote       = $risk
            Recommendation = $reco
        }

        [void]$Print.Add($OFA)
    }

    return $Print
}

