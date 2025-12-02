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

            return [PSCustomObject]@{
                Hostname       = $compInfo.Name
                OSRole         = $osRole
                HardwareType   = $hardwareType
                Manufacturer   = $compInfo.Manufacturer
                Model          = $compInfo.Model
                IsDomainJoined = $compInfo.PartOfDomain
                Timestamp      = (Get-Date)
            }
        }
        catch {
            Write-Error "Erreur Context: $_"
            return $null
        }
    }
}