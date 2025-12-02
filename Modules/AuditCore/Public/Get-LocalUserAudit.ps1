function Get-LocalUserAudit {
    <#
    .SYNOPSIS
        Audite les comptes utilisateurs locaux et le groupe Administrateurs.

    .DESCRIPTION
        Cette fonction vérifie :
        - L'état du compte Administrateur intégré (SID -500).
        - L'état du compte Invité (SID -501).
        - La présence d'autres utilisateurs dans le groupe Administrateurs local.

    .OUTPUTS
        PSCustomObject

    .EXAMPLE
        Get-LocalUserAudit
    #>
    [CmdletBinding()]
    param()

    process {

        # Recommandations Builtin Admin
        $RecoBuiltinAdminEnabled = ""
        $RecoBuiltinAdminDisabled = ""

        # Recommandation Builtin Guest
        $RecoBuiltinGuestEnabled = ""
        $RecoBuiltinGuestDisabled = ""

        try {
            # Récupération de tous les utilisateurs locaux
            # On utilise ErrorAction Stop pour attraper l'erreur si on est sur un DC (où il n'y a pas d'utilisateurs locaux classiques)
            $localUsers = Get-LocalUser -ErrorAction Stop

            # --- 1. Analyse du compte Administrateur (SID finit par -500) ---
            $builtInAdmin = $localUsers | Where-Object { $_.SID.Value -match "-500$" }
            
            # --- 2. Analyse du compte Invité (SID finit par -501) ---
            $builtInGuest = $localUsers | Where-Object { $_.SID.Value -match "-501$" }

            # --- 3. Analyse du groupe Administrateurs (SID S-1-5-32-544) ---
            # On récupère les membres du groupe Admin local
            $adminGroupMembers = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue

            # On filtre pour trouver les admins qui NE SONT PAS le compte Administrateur intégré (-500)
            # C'est important pour repérer les comptes créés manuellement qui ont les pleins pouvoirs
            $otherAdmins = $adminGroupMembers | Where-Object { $_.SID.Value -ne $builtInAdmin.SID.Value }

            # --- 4. Construction de l'objet de résultat ---
            $auditObject = [PSCustomObject]@{

                AdminAccountName    = $builtInAdmin.Name
                AdminAccountSID     = $builtInAdmin.SID.Value
                AdminEnabled        = $builtInAdmin.Enabled # Devrait être False par sécurité
                AdminRecommandation = @{
                    Enabled = $RecoBuiltinAdminEnabled
                    Disabled = $RecoBuiltinAdminDisabled
                }
                GuestAccountName    = $builtInGuest.Name
                GuestAccountSID     = $builtInGuest.SID.Value
                GuestEnabled        = $builtInGuest.Enabled # Devrait être False
                GuestRecommandation = @{
                    Enabled = $RecoBuiltinGuestEnabled
                    Disabled = $RecoBuiltinGuestDisabled
                }
                OtherAdminsCount    = if ($otherAdmins) { $otherAdmins.Count } else { 0 }
                OtherAdminsList     = if ($otherAdmins) { ($otherAdmins.Name -join ", ") } else { "None" }
                Timestamp           = (Get-Date)
            }

            return $auditObject

        }
        catch {
            # Gestion spécifique si on est sur un contrôleur de domaine (pas d'utilisateurs locaux)
            if ($_.Exception.GetType().Name -match "PrincipalNotFound|NoUserFound") {
                 Write-Warning "Impossible d'auditer les utilisateurs locaux (Probablement un Contrôleur de Domaine)."
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