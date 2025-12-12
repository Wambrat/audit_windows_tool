function Get-ServerAntivirusStatus {
    [CmdletBinding()]
    param ()

    $antivirusStatus = @()

    
    $isDC = Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole

    $isDomainController = $isDC -ge 4
    
    $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($defenderService) {
        $status = $defenderService.Status -eq "Running"
        $antivirusStatus += [PSCustomObject]@{
            Name = "Microsoft Defender Antivirus"
            Present = $true
            Enabled = $status
        }
    }

    
    $avServices = Get-CimInstance -ClassName Win32_Service |
                  Where-Object { $_.DisplayName -match "(Antivirus|Defend|Symantec|McAfee|TrendMicro|CrowdStrike|ESET)" }

    foreach ($service in $avServices) {
        if($isDomainController -and $service.DisplayName -notmatch "Defender"){

            $antivirusStatus += [PSCustomObject]@{
                Name = $service.DisplayName
                Present = $true
                Enabled = ($service.State -eq "Running")
                Description = "Machine is a domain controller, third-party solutions are not recommended."
            }

        }else{

            $antivirusStatus += [PSCustomObject]@{
                Name = $service.DisplayName
                Present = $true
                Enabled = ($service.State -eq "Running")
            }

        }



    }

    if (-not $antivirusStatus) {
        $antivirusStatus += [PSCustomObject]@{
            Name = "No antivirus detected"
            Present = $false
            Enabled = $false
        }
    }

    return $antivirusStatus
}
