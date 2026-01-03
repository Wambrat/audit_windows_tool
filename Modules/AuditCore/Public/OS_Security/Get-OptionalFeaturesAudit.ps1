function Get-OptionalFeaturesAudit {
    [CmdletBinding()]
    param()

    $Print = [System.Collections.ArrayList]@()

    $features = Get-WindowsOptionalFeature -Online |
                Where-Object State -eq 'Enabled' |
                Sort-Object FeatureName

    foreach ($f in $features) {

        $risk = switch -Wildcard ($f.FeatureName) {
            'IIS*'         { 'Potentially exposed web service (IIS); increases attack surface if Internet-facing.' }
            'TelnetClient' { 'Obsolete and insecure protocol (Telnet sends credentials in clear text).' }
            'SMB1Protocol' { 'Legacy and vulnerable file sharing protocol (SMBv1); should be removed.' }
            'TFTPClient'   { 'Insecure file transfer protocol (TFTP) without authentication or encryption.' }
            'FTP*'         { 'Unencrypted file transfer; should be restricted or replaced with SFTP/FTPS.' }
            'Hyper-V*'     { 'Virtualization role; keep only on hosts dedicated to virtualization or labs.' }
            'WCF-*HTTP*'   { 'HTTP-exposed WCF components; verify they are required and properly hardened.' }
            Default        { '' }
        }

        $reco = if ($risk) {
            'Remove or disable this feature if it is not strictly required, and ensure it is not exposed to untrusted networks.'
        }
        else {
            'Review whether this optional feature is actually used; disable it if not needed to reduce attack surface.'
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
