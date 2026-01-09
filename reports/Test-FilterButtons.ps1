# Test Script for Filter Buttons
$testData = [PSCustomObject]@{
    HostContext = [PSCustomObject]@{
        ComputerName = "TEST-PC"
        OSVersion = "Windows 10"
    }
    Firewall = [PSCustomObject]@{
        FirewallStatus = $true
        DomainProfileEnabled = $true
    }
    BitLocker = [PSCustomObject]@{
        BitLockerStatus = $false
        EncryptionPercentage = 0
    }
    UAC = [PSCustomObject]@{
        UACEnabled = $true
        ConsentPromptBehavior = "Prompt for credentials"
    }
    Updates = [PSCustomObject]@{
        AutomaticUpdatesEnabled = $true
        LastUpdateCheck = "2025-01-15"
    }
    Antivirus = [PSCustomObject]@{
        AntivirusProduct = "Windows Defender"
        RealtimeProtection = $false
    }
}

# Load and run the report script
& ".\reports\ReportAuditHTML.ps1" -AuditResults $testData

Write-Host "Test report generated successfully!" -ForegroundColor Green
