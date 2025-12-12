function Get-DomainState {
    [CmdletBinding()]
    param()

    process{

        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $DomainState = [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Domain       = $cs.Domain
            PartOfDomain = $cs.PartOfDomain
        }

        Return $DomainState

    }


}
