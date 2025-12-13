function Get-HostContext {
    <#
    .SYNOPSIS
        Récupère le contexte de l'hôte (Type de machine, Environnement, OS).
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

            return [PSCustomObject]@{
                Hostname       = $compInfo.Name
                OSRole         = $osRole
                HardwareType   = $hardwareType
                Manufacturer   = $compInfo.Manufacturer
                Model          = $compInfo.Model
                IsDomainJoined = $compInfo.PartOfDomain
                Timestamp      = (Get-Date)

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
