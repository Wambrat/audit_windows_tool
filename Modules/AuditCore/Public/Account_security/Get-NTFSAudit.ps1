function Get-NTFSAudit {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Path,

        [parameter(Mandatory=$false)]
        [string]$User
    )

    process {
        # 1. Récupération de l'ACL
        $ACL = Get-Acl -Path $Path -ErrorAction SilentlyContinue

        if (-not $ACL) {
            Write-Warning "Impossible d'accéder à : $Path"
            return $null
        }

        # 2. Récupérer et cumuler les droits (Bitwise OR)
        $Rules = $ACL.Access | Where-Object { 
            ($_.IdentityReference.Value -match $User) -and  
            ($_.AccessControlType -eq 'Allow') 
        }

        [int]$CumulativeRights = 0
        if ($Rules) {
            foreach ($Rule in $Rules) {
                $CumulativeRights = $CumulativeRights -bor [int]$Rule.FileSystemRights
            }
        }

        # 3. Calcul des booléens (Vrai/Faux)
        $FullControlMask = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        $WriteMask       = [int][System.Security.AccessControl.FileSystemRights]::Write
        $ReadMask        = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute

        $IsFullControl = ($CumulativeRights -band $FullControlMask) -eq $FullControlMask
        $CanWrite      = ($CumulativeRights -band $WriteMask) -eq $WriteMask
        $CanRead       = ($CumulativeRights -band $ReadMask)  -eq $ReadMask

        # 4. Détermination du label "Status" pour lecture humaine rapide
        $Status = "None"
        if ($IsFullControl) { $Status = "FullControl" }
        elseif ($CanWrite -and $CanRead) { $Status = "Read/Write" }
        elseif ($CanWrite) { $Status = "WriteOnly" }
        elseif ($CanRead) { $Status = "ReadOnly" }
        elseif ($CumulativeRights -ne 0) { $Status = "Custom" }

        # 5. RETOUR DE L'OBJET
        [PSCustomObject]@{
            Path          = $Path
            User          = $User
            Status        = $Status         # Résumé textuel
            IsFullControl = $IsFullControl  # Booléen
            CanWrite      = $CanWrite       # Booléen
            CanRead       = $CanRead        # Booléen
            RawRights     = $CumulativeRights # Valeur numérique (debug)
        }
    }
}