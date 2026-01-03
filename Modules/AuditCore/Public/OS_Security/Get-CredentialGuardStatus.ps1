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
        1     { $config = 'Enabled with UEFI lock' }
        2     { $config = 'Enabled without UEFI lock' }
        0     { $config = 'Disabled' }
        $null { $config = 'Not configured (default behavior)' }
        default { $config = "Unknown value ($cfg)" }
    }

    $cs  = Get-CimInstance -ClassName Win32_ComputerSystem
    $tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $efi = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $virt = $cs.HypervisorPresent

    # TPM 1.2 minimum, 2.0 recommended
    $hasTPM = $tpm -and ($tpm.SpecVersion -match '1\.2' -or $tpm.SpecVersion -match '2\.0')

    $reco = @()

    if (-not $hasTPM) { $reco += 'Deploy or enable a TPM chip (version 1.2 minimum, 2.0 recommended) to support Credential Guard.' }
    if (-not $efi)    { $reco += 'Enable UEFI firmware with Secure Boot to harden Credential Guard and boot integrity.' }
    if (-not $virt)   { $reco += 'Enable hardware virtualization (VT-x or AMD-V) and Hyper-V/VBS to allow Credential Guard isolation.' }

    if ($cfg -eq 0 -or $cfg -eq $null) {
        $reco += 'Enable Credential Guard (LsaCfgFlags set to 1 or 2) once all prerequisites are met and tested in a pilot group.'
    } else {
        $reco += 'Credential Guard is enabled; regularly verify compatibility and keep firmware/OS fully patched.'
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
