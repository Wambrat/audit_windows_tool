function Get-OptionalFeaturesAudit {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $features = Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | Sort-Object FeatureName

    foreach ($f in $features) {

        $risk = switch -Wildcard ($f.FeatureName) {
            'IIS*'            { 'Potentially exposed (IIS)' }
            'TelnetClient'    { 'Obsolete / dangerous (Telnet)' }
            'SMB1Protocol'    { 'Obsolete / vulnerable (SMBv1)' }
            'TFTPClient'      { 'Not secure (unencrypted TFTP)' }
            'FTP*'            { 'Unsafe / to be limited (FTP)' }
            'Hyper-V*'        { 'Keep only if virtualization is required' }
            'WCF-*HTTP*'      { 'Potential network exposure' }
            default           { '' }
        }

        $reco =
            if ($risk) {
                "Remove if not strictly necessary."
            } else {
                'Check usefulness, delete if not used.'
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
