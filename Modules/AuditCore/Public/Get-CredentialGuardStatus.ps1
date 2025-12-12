function Get-CredentialGuardStatus {
    [CmdletBinding()]
    param()

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    $cfg = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).LsaCfgFlags

    if ($cfg -eq $null){
        $cfg = (Get-ItemProperty -Path $path -ErrorAction Stop).LsaCfgFlagsDefault
    }

    switch ($cfg) {
        1 { $config = 'Enabled with UEFI lock' }
        2 { $config = 'Enabled without UEFI lock' }
        0 { $config = 'Disabled' }
        $null { $config = 'Not configured (default behavior)' }
        default { $config = "Unknown value ($cfg)" }
    }

    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $tpm  = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $efi  = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $virt = $cs.HypervisorPresent

    $hasTPM = $tpm -and $tpm.SpecVersion -match '1\.2|2\.0'

    $reco = @()

    if (-not $hasTPM) { $reco += 'Activate/add a TPM chip (1.2 minimum, ideally 2.0).' }
    if (-not $efi)    { $reco += 'Enable UEFI + Secure Boot.' }
    if (-not $virt)   { $reco += 'Enable virtualization (VT-x/AMD-V + Hyper-V) for Credential Guard.' }

    if ($cfg -eq 0 -or $cfg -eq $null) {
        $reco += 'Activate Credential Guard (LsaCfgFlags=1 or 2) when the prerequisites are met.'
    } else {
        $reco += 'Credential Guard already activated.'
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
