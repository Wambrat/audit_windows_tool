function Get-LocalUserAudit {
    <#
    .SYNOPSIS
        Audite les comptes utilisateurs locaux et le groupe Administrateurs.

    .DESCRIPTION
        Cette fonction v�rifie :
        - L'�tat du compte Administrateur int�gr� (SID -500).
        - L'�tat du compte Invit� (SID -501).
        - La pr�sence d'autres utilisateurs dans le groupe Administrateurs local.

    .OUTPUTS
        PSCustomObject

    .EXAMPLE
        Get-LocalUserAudit
    #>
    [CmdletBinding()]
    param()

    process {

        # Recommandations Builtin Admin
        $RecoBuiltinAdminEnabled = "`rLe compte Administrateur (SID-500) est activ�. C'est une cible privil�gi�e car son SID est connu de tous.`rRecommandation : D�sactivez-le et utilisez des comptes nominatifs ou LAPS."
        $RecoBuiltinAdminDisabled = "`rLe compte Administrateur par d�faut est d�sactiv� r�duisant la surface d'attaque."

        # Recommandation Builtin Guest
        $RecoBuiltinGuestEnabled = "`rLe compte Invit� est activ�. Cela peut permettre un acc�s anonyme ou non trac� au syst�me. Recommandation : D�sactivez ce compte imm�diatement."
        $RecoBuiltinGuestDisabled = "`rLe compte Invit� est bien d�sactiv�."

        try {
            # R�cup�ration de tous les utilisateurs locaux
            # On utilise ErrorAction Stop pour attraper l'erreur si on est sur un DC (o� il n'y a pas d'utilisateurs locaux classiques)
            $localUsers = Get-LocalUser -ErrorAction Stop

            # --- 1. Analyse du compte Administrateur (SID finit par -500) ---
            $builtInAdmin = $localUsers | Where-Object { $_.SID.Value -match "-500$" }
            
            # --- 2. Analyse du compte Invit� (SID finit par -501) ---
            $builtInGuest = $localUsers | Where-Object { $_.SID.Value -match "-501$" }

            # --- 3. Analyse du groupe Administrateurs (SID S-1-5-32-544) ---
            # On r�cup�re les membres du groupe Admin local
            $adminGroupMembers = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue

            # On filtre pour trouver les admins qui NE SONT PAS le compte Administrateur int�gr� (-500)
            # C'est important pour rep�rer les comptes cr��s manuellement qui ont les pleins pouvoirs
            $otherAdmins = $adminGroupMembers | Where-Object { $_.SID.Value -ne $builtInAdmin.SID.Value }

            # --- 4. Construction de l'objet de r�sultat ---
            $auditObject = [PSCustomObject]@{

                AdminAccountName    = $builtInAdmin.Name
                AdminAccountSID     = $builtInAdmin.SID.Value
                AdminEnabled        = $builtInAdmin.Enabled # Devrait �tre False par s�curit�
                AdminRecommandation = @{
                    Enabled  = $RecoBuiltinAdminEnabled
                    Disabled = $RecoBuiltinAdminDisabled
                }
                GuestAccountName    = $builtInGuest.Name
                GuestAccountSID     = $builtInGuest.SID.Value
                GuestEnabled        = $builtInGuest.Enabled # Devrait �tre False
                GuestRecommandation = @{
                    Enabled  = $RecoBuiltinGuestEnabled
                    Disabled = $RecoBuiltinGuestDisabled
                }
                OtherAdminsCount    = if ($otherAdmins) { $otherAdmins.Count } else { 0 }
                OtherAdminsList     = if ($otherAdmins) { ($otherAdmins.Name -join ", ") } else { "None" }
                Timestamp           = (Get-Date)
            }

            return $auditObject

        }
        catch {
            # Gestion sp�cifique si on est sur un contr�leur de domaine (pas d'utilisateurs locaux)
            if ($_.Exception.GetType().Name -match "PrincipalNotFound|NoUserFound") {
                 Write-Warning "Impossible d'auditer les utilisateurs locaux (Probablement un Contr�leur de Domaine)."
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