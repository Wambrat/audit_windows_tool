function Get-LsassProtectionStatus {
    [CmdletBinding()]
    param()

    $lsaPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

    $runAsPPL = (Get-ItemProperty -Path $lsaPath -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
    $useLogon = (Get-ItemProperty -Path $wdigestPath -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    $desc = @()

    switch($runAsPPL){
        
        2{$desc += 'LSA : LSA protection (RunAsPPL) enabled with Secure Boot required'}
        1{$desc += 'LSA : LSA protection (RunAsPPL) enabled without Secure Boot required'}
        Default{$desc += 'LSA : Unknown value or non-existent key, LSA protection disabled'}

    }

    switch($useLogon){
        
        1{$desc += 'WDigest: Disable WDigest (UseLogonCredential=0) to prevent passwords from being stored in plain text.'}
        0{$desc += 'WDigest: WDigest disabled or not configured in a dangerous way.'}
        Default{$desc += 'WDigest: Key does not exist, create it and set it to 0'}


    }

    $ProtectionStatus = [pscustomobject]@{
        LsaPath              = $lsaPath
        RunAsPPL             = $runAsPPL
        WDigestPath          = $wdigestPath
        UseLogonCredential   = if($useLogon){$useLogon}else{"N/A"}
        Description          = $desc -join ' | '
    }

    Return $ProtectionStatus

}
