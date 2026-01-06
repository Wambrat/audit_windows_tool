function Get-HostContext {
    <#
    .SYNOPSIS
        Recupere le contexte de l'hote (Type de machine, Environnement, OS).
    #>
    [CmdletBinding()]
    param()

    process {
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $compInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

            $osRole = if ($osInfo.ProductType -eq 1) { "Workstation" } else { "Server" }

            $modelStr = "$($compInfo.Manufacturer) $($compInfo.Model)"
            $isVirtual = $modelStr -match "VMware|Virtual|Hyper-V|KVM|Xen|Bochs|QEMU"
            $hardwareType = if ($isVirtual) { "Virtual Machine" } else { "Physical" }

            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [System.Security.Principal.WindowsPrincipal]$identity
            
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

            # récupérer le context réseau de la machine incluant le nom d'hote, l'adresse IP et le domaine
            $networkInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
            $ipAddresses = $networkInfo.IPAddress -join ", "
            $domainName = $compInfo.Domain

            return [PSCustomObject]@{
                Hostname       = $compInfo.Name
                OSRole         = $osRole
                HardwareType   = $hardwareType
                Manufacturer   = $compInfo.Manufacturer
                Model          = $compInfo.Model
                IsDomainJoined = $compInfo.PartOfDomain
                Timestamp      = (Get-Date)
                IPAddresses    = $ipAddresses
                DomainName     = $domainName

                CurrentUser    = $identity.Name
                IsRunAsAdmin   = $isAdmin

            }
        }
        catch {
            Write-Error "Erreur Context: $_"
            return $null
        }
    }
}

