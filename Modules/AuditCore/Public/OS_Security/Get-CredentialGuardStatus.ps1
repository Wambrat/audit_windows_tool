function Get-CredentialGuardStatus {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    # Read LsaCfgFlags or fallback to LsaCfgFlagsDefault if not explicitly set
    $lsaProps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    $cfg = $lsaProps.LsaCfgFlags

    if ($cfg -eq $null) {
        $cfg = $lsaProps.LsaCfgFlagsDefault
    }

    switch ($cfg) {
        1       { $config = 'Active avec le verrouillage UEFI' }
        2       { $config = 'Active sans verrouillage UEFI' }
        0       { $config = 'Desactive' }
        $null   { $config = 'Non configure (comportement par defaut)' }
        default { $config = "Valeur inconnue ($cfg)" }
    }

    $cs  = Get-CimInstance -ClassName Win32_ComputerSystem
    $tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $efi = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $virt = $cs.HypervisorPresent

    # TPM 1.2 minimum, 2.0 recommended
    $hasTPM = $tpm -and ($tpm.SpecVersion -match '1\.2' -or $tpm.SpecVersion -match '2\.0')

    $reco = @()

    if (-not $hasTPM) { $reco += "Deployez ou activez une puce TPM (version 1.2 minimum, 2.0 recommandee) pour prendre en charge Credential Guard." }
    if (-not $efi)    { $reco += "Activez le micrologiciel UEFI avec Secure Boot pour renforcer Credential Guard et l'integrite du demarrage." }
    if (-not $virt)   { $reco += "Activez la virtualisation materielle (VT-x ou AMD-V) et Hyper-V/VBS pour permettre l'isolation Credential Guard." }

    if ($cfg -eq 0 -or $cfg -eq $null) {
        $reco += "Activez Credential Guard (LsaCfgFlags defini sur 1 ou 2) une fois que toutes les conditions prealables sont remplies et testees dans un groupe pilote."
    } else {
        $reco += "Credential Guard est active; verifiez regulierement la compatibilite et gardez le micrologiciel/systeme d'exploitation à jour"
    }

    [pscustomobject]@{
        LsaPath         = $path
        LsaCfgFlags     = $cfg
        CredentialGuard = $config
        HasTPM          = [bool]$hasTPM
        SecureBoot      = $efi
        Virtualization  = $virt
        Recommendations = $reco -join '; '
    }
}

