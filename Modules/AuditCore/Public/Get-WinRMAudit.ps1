function Get-WinRMAudit {
    [CmdletBinding()]
    param()


    $Service = Get-Service WinRM -ErrorAction SilentlyContinue



    if($Service.Status -eq "Stopped"){
        
        $WinRMInfo = [pscustomobject]@{
            WinRmEnabled = $false
        }


    }else{

        [xml]$Listeners   = (winrm enumerate winrm/config/listener -format:xml 2>$null)
        [xml]$Service     = (winrm get winrm/config/service -format:xml 2>$null)
        [xml]$Client     = (winrm get winrm/config/client -format:xml 2>$null)

        $RemoteMgmtUsers = Get-LocalGroupMember -SID S-1-5-32-580
        $AdminUsers = Get-LocalGroupMember -SID S-1-5-32-544

        $RmOnly = $RemoteMgmtUsers | Where-Object {
            $name = $_.Name
            -not ($AdminUsers.Name -contains $name)
        }

        $WinRMInfo = [pscustomobject]@{
                    WinRmEnabled = $true
                    ListenerTransport = $listeners.ChildNodes.Listener.Transport
                    ListeningOn = $listeners.ChildNodes.Listener.ListeningOn
                    IPv4Filter = $Service.Service.IPv4Filter
                    IPv6Filter = $Service.Service.IPv6Filter
                    ServiceAuth = $Service.Service.Auth
                    ClientAuth = $Client.Client.Auth
                    RmUsersNotAdmins  = $RmOnly.Name
                }

    }

    return $WinRMInfo
}