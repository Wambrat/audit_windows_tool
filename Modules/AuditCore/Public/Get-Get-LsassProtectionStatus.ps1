function Get-LsassProtectionStatus {
    [CmdletBinding()]
    param()

    $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

    $runAsPPL = (Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    $useLogon = (Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    $desc = @()

    switch($runAsPPL){
        
        2{$desc += 'LSA : LSA protection (RunAsPPL) activée avec Secure Boot obligatoire'}
        1{$desc += 'LSA : LSA protection (RunAsPPL) activée sans Secure Boot obligatoire'}
        Default{$desc += 'LSA : Valeur inconnu ou clé inexistante, LSA protection désactivée'}

    }

    switch($useLogon){
        
        1{$desc += 'WDigest : Désactiver WDigest (UseLogonCredential=0) pour éviter le stockage des mots de passe en clair.'}
        0{$desc += 'WDigest : WDigest désactivé ou non configuré de façon dangereuse.'}
        Default{$desc += 'WDigest : Clé inexistante, la créer et la mettre a 0'}


    }

    # Pour la reco "supprimer Administrateur de debug programs", il faudra lire les droits locaux
    # (SeDebugPrivilege) via ntrights/secedit ou module spécialisé, plus lourd à coder.

    [pscustomobject]@{
        LsaPath              = $lsaPath
        RunAsPPL             = $runAsPPL
        WDigestPath          = $wdigestPath
        UseLogonCredential   = if($useLogon){$useLogon}else{"N/A"}
        Description          = $desc -join ' | '
    }
}
