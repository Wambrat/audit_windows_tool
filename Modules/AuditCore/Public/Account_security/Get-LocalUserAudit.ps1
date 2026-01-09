function Get-LocalUserAudit {
    <#
    .SYNOPSIS
        Audite les comptes utilisateurs locaux et le groupe Administrateurs.

    .DESCRIPTION
        Cette fonction vérifie :
        - L'etat du compte Administrateur integre (SID -500).
        - L'etat du compte Invite (SID -501).
        - La presence d'autres utilisateurs dans le groupe Administrateurs local.

    .OUTPUTS
        PSCustomObject

    .EXAMPLE
        Get-LocalUserAudit
    #>
    [CmdletBinding()]
    param()

    process {

        # Recommandations Builtin Admin
        $RecoBuiltinAdminEnabled = "`rLe compte Administrateur (SID-500) est active. C'est une cible privilegiee car son SID est connu de tous.`rRecommandation : Desactivez-le et utilisez des comptes nominatifs ou LAPS."
        $RecoBuiltinAdminDisabled = "`rLe compte Administrateur par defaut est desactive reduisant la surface d'attaque."

        # Recommandation Builtin Guest
        $RecoBuiltinGuestEnabled = "`rLe compte Invite est active. Cela peut permettre un acces anonyme ou non trace au systeme. Recommandation : Desactivez ce compte immediatement."
        $RecoBuiltinGuestDisabled = "`rLe compte Invite est bien desactive."

        try {
            # Recuperation de tous les utilisateurs locaux
            # On utilise ErrorAction Stop pour attraper l'erreur si on est sur un DC (où il n'y a pas d'utilisateurs locaux classiques)
            $localUsers = Get-LocalUser -ErrorAction Stop

            # --- 1. Analyse du compte Administrateur (SID finit par -500) ---
            $builtInAdmin = $localUsers | Where-Object { $_.SID.Value -match "-500$" }
            
            # --- 2. Analyse du compte Invite (SID finit par -501) ---
            $builtInGuest = $localUsers | Where-Object { $_.SID.Value -match "-501$" }

            # --- 3. Analyse du groupe Administrateurs (SID S-1-5-32-544) ---
            # On recupere les membres du groupe Admin local
            $adminGroupMembers = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue

            # On filtre pour trouver les admins qui NE SONT PAS le compte Administrateur integre (-500)
            # C'est important pour reperer les comptes crees manuellement qui ont les pleins pouvoirs
            $otherAdmins = $adminGroupMembers | Where-Object { $_.SID.Value -ne $builtInAdmin.SID.Value }

            # --- 4. Construction de l'objet de resultat ---
            $auditObject = [PSCustomObject]@{

                AdminAccountName    = $builtInAdmin.Name
                AdminAccountSID     = $builtInAdmin.SID.Value
                AdminEnabled        = $builtInAdmin.Enabled # Devrait etre False par securite
                AdminRecommandation = @{
                    Enabled  = $RecoBuiltinAdminEnabled
                    Disabled = $RecoBuiltinAdminDisabled
                }
                GuestAccountName    = $builtInGuest.Name
                GuestAccountSID     = $builtInGuest.SID.Value
                GuestEnabled        = $builtInGuest.Enabled # Devrait etre False
                GuestRecommandation = @{
                    Enabled  = $RecoBuiltinGuestEnabled
                    Disabled = $RecoBuiltinGuestDisabled
                }
                OtherAdminsCount    = if ($otherAdmins) { $otherAdmins.Count } else { 0 }
                OtherAdminsList     = if ($otherAdmins) { ($otherAdmins.Name -join ", ") } else { "None" }
                
                Timestamp           = (Get-Date)
            }

            $Xml = if ($builtInGuest.Enabled -eq $true) {
                    [pscustomobject]@{
                        Category    = "LocalUserAudit_GuestAccount"
                        Description = "Desactivez le compte Invite pour reduire les risques d'acces anonyme."
                        Command     = "Disable-LocalUser -Name '$($builtInGuest.Name)'"
                    }
                } else {
                    $null
                }


            return [PSCustomObject]@{
                Value = $auditObject
                Xml   = $Xml
            }

        }
        catch {
            # Gestion specifique si on est sur un contreleur de domaine (pas d'utilisateurs locaux)
            if ($_.Exception.GetType().Name -match "PrincipalNotFound|NoUserFound") {
                 Write-Warning "Impossible d'auditer les utilisateurs locaux (Probablement un Controleur de Domaine)."
                 return $null
            }
            
            Write-Error "Erreur lors de l'audit des utilisateurs : $_"
            return [PSCustomObject]@{
                Error     = $_.Exception.Message
                Timestamp = (Get-Date)
            }
        }
    }
}
