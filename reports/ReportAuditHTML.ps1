param(
    [Parameter(Mandatory=$true)]
    [PSObject]$AuditResults,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ""
)

# Si pas de OutputPath fourni, utiliser le répertoire courant
if ([string]::IsNullOrEmpty($OutputPath)) {
    if (-not (Test-Path -Path "$(Get-Location)\reports")) {
        New-Item -ItemType Directory -Path "$(Get-Location)\reports" | Out-Null
    }

    $OutputPath = "$(Get-Location)\reports\audits\Audit_Report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
}

# Configuration
$ErrorActionPreference = "Stop"

# Fonctions Utilitaires
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return "" }
    return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
}

function Get-VulnerabilityScore {
    param([PSObject]$Results)
    
    $totalChecks = 0
    $passedChecks = 0
    
    try {
        foreach ($categoryProp in $Results.PSObject.Properties) {
            if ($categoryProp.Value -is [PSObject]) {
                foreach ($itemProp in $categoryProp.Value.PSObject.Properties) {
                    $totalChecks++
                    $itemValue = $itemProp.Value
                    
                    if ($itemValue -eq $true -or $itemValue -eq "Enabled" -or $itemValue -eq "Configured" -or $itemValue -eq "OK") {
                        $passedChecks++
                    }
                }
            }
        }
    } catch {
        Write-Host "Erreur dans Get-VulnerabilityScore: $_" -ForegroundColor Red
    }
    
    if ($totalChecks -eq 0) { return @{ Score = 0; Total = 0; Percentage = 0 } }
    
    return @{
        Score = $passedChecks
        Total = $totalChecks
        Percentage = [Math]::Round(($passedChecks / $totalChecks) * 100, 2)
    }
}

function Get-StatusColor {
    param([bool]$IsGood)
    if ($IsGood) { return "#28a745" } else { return "#dc3545" }
}

function Get-StatusBadge {
    param([bool]$IsGood)
    $color = Get-StatusColor $IsGood
    $text = if ($IsGood) { "COMPLIANT" } else { "NON COMPLIANT" }
    $bgColor = if ($IsGood) { "#d4edda" } else { "#f8d7da" }
    return "<span class='badge' style='background-color: $bgColor; color: $color;'>$text</span>"
}

function Get-AutomationStatus {
    param([string]$ItemName)
    
    # Liste des éléments automatisables
    $automatisableItems = @(
        "BitLocker", "Firewall", "Updates", "UAC", "SMB", "Network",
        "BitLockerEnabled", "FirewallStatus", "DomainProfile", "AutoUpdates",
        "UACEnabled", "SMBSigning", "CredentialGuard", "DefenderStatus",
        "WindowsUpdates", "LsassProtection", "AppLocker", "Exploit"
    )
    
    foreach ($keyword in $automatisableItems) {
        if ($ItemName -like "*$keyword*") {
            return "auto"
        }
    }
    return "manual"
}

function Get-AutomatisableBadge {
    param([string]$ItemName)
    
    $automationStatus = Get-AutomationStatus -ItemName $ItemName
    
    $bgColor = if ($automationStatus -eq "auto") { "#d1ecf1" } else { "#fff3cd" }
    $color = if ($automationStatus -eq "auto") { "#0c5460" } else { "#856404" }
    $text = if ($automationStatus -eq "auto") { "Automatable" } else { "Manual" }
    
    return "<span class='badge' style='background-color: $bgColor; color: $color;'>$text</span>"
}

$style = Get-Content -Path "$(Split-Path -Parent $PSCommandPath)\stylesAudit.css" -Raw
$script = Get-Content -Path "$(Split-Path -Parent $PSCommandPath)\scriptAudit.js" -Raw

# Generation du Rapport HTML
$scoreInfo = Get-VulnerabilityScore -Results $AuditResults
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Extraire les info de HostContext de manière sécurisée
$computerName = ""
$osInfo = ""
if ($AuditResults.PSObject.Properties.Name -contains "HostContext") {
    $hostContext = $AuditResults.HostContext
    if ($hostContext) {
        $computerName = if ($hostContext.PSObject.Properties.Name -contains "ComputerName") { $hostContext.ComputerName } else { "" }
        $osInfo = if ($hostContext.PSObject.Properties.Name -contains "OSVersion") { $hostContext.OSVersion } else { "" }
    }
}

$computerName = if ([string]::IsNullOrWhiteSpace($computerName)) { "Unknown" } else { $computerName.Trim() }
$osInfo = if ([string]::IsNullOrWhiteSpace($osInfo)) { "Unknown" } else { $osInfo.Trim() }

$htmlContent = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Audit Report - $computerName</title>
</head>
<body>
    <div class="container">
        <header>
            <h1>Windows Security Audit Report</h1>
            <p>Complete System Security Audit</p>
        </header>
        
        <div class="content">
            <div class="score-section">
                <h2 style="margin-bottom: 20px;">Security Score</h2>
                <div class="score-circle">
                    <div class="score-number">$($scoreInfo.Score)</div>
                    <div class="score-total">/$($scoreInfo.Total)</div>
                </div>
                <div class="score-percentage">$($scoreInfo.Percentage)%</div>
                <p style="margin-top: 15px;">Based on the number of valid security controls</p>
            </div>
            
            <div class="system-info">
                <h2>System Information</h2>
                <div class="system-info-grid">
                    <div class="info-item">
                        <div class="info-label">Computer Name</div>
                        <div class="info-value">$(ConvertTo-HtmlSafe $computerName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Operating System</div>
                        <div class="info-value">$(ConvertTo-HtmlSafe $osInfo)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Report Date</div>
                        <div class="info-value">$timestamp</div>
                    </div>
                </div>
            </div>
            
            <div class="search-section">
                <input type="text" class="search-box" id="searchInput" placeholder="Search for a vulnerability...">
            </div>
            
            <div class="filter-section">
                <div class="filter-group">
                    <strong>Vulnerabilities:</strong>
                    <button class="filter-btn good-btn" data-filter="status" data-value="good">Good</button>
                    <button class="filter-btn bad-btn" data-filter="status" data-value="bad">Bad</button>
                </div>
                <div class="filter-group">
                    <strong>Remediations:</strong>
                    <button class="filter-btn auto-btn" data-filter="automation" data-value="auto">Automatic</button>
                    <button class="filter-btn manual-btn" data-filter="automation" data-value="manual">Manual</button>
                </div>
            </div>
            
            <h2 style="color: #667eea; margin-bottom: 20px; margin-top: 30px;">Vulnerabilities Summary</h2>
            <div class="vulnerabilities-list" id="vulnerabilitiesList">
"@

# Generation de la liste des vulnerabilites
$vulnerabilityCount = 0
foreach ($categoryProp in $AuditResults.PSObject.Properties) {
    $categoryName = $categoryProp.Name
    $categoryValue = $categoryProp.Value
    
    # Exclure HostContext de la liste des vulnérabilités
    if ($categoryName -eq "HostContext") {
        continue
    }
    
    if ($categoryValue -is [PSObject]) {
        foreach ($itemProp in $categoryValue.PSObject.Properties) {
            $vulnerabilityCount++
            $itemName = $itemProp.Name
            $itemValue = $itemProp.Value
            
            $isGood = $false
            if ($itemValue -eq $true -or $itemValue -eq "Enabled" -or $itemValue -eq "Configured" -or $itemValue -eq "OK") {
                $isGood = $true
            }
            
            if ($isGood) { 
                $statusClass = "good"
                $recommendation = "None"
            } else {
                $statusClass = "bad"
                # $recommendation = $itemProp.recommandations
                $recommendation = "Please verify the configuration of $itemName and apply appropriate security recommendations."
            }
            $statusBadge = Get-StatusBadge -IsGood $isGood
            $automatisableBadge = Get-AutomatisableBadge -ItemName $itemName
            $automationStatus = Get-AutomationStatus -ItemName $itemName
            $displayValue = ConvertTo-HtmlSafe $itemValue
            
            $htmlContent += @"
                <div class="vulnerability-item $statusClass" data-automation="$automationStatus" onclick="toggleDetails(this)">
                    <h3>
                        <span>$itemName</span>
                        <span class="status">$statusBadge $automatisableBadge</span>
                    </h3>
                    <div class="details" style="display: none;">
                        <div class="details-label">Category:</div>
                        <div class="details-content">$categoryName</div>
                        <div class="details-label">Status:</div>
                        <div class="details-content">$displayValue</div>
                        <div class="details-label">Automatable:</div>
                        <div class="details-content">$(if ($automatisableBadge -like "*Automatable*") { "Yes - This remediation can be automated via PowerShell/GPO" } else { "No - This remediation requires manual intervention" })</div>
                        <div class="recommendation" style="display: $(if ($recommendation -and $recommendation -ne "None") { "block" } else { "none" });">
                            <strong>Recommandation:</strong><br>
                            $recommendation
                        </div>
                    </div>
                </div>
"@
        }
    }
}

$htmlContent += @"
            </div>
        </div>
        
        <footer>
            <p>Report generated by Windows Audit Tool | $timestamp</p>
            <p>This audit provides an overview of security configurations. For more details, consult the system logs.</p>
        </footer>
    </div>
    <style>
        $style
    </style>
    <script>
        $script
    </script>
</body>
</html>
"@

# Export du Rapport
try {
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "[OK] Rapport genere avec succes: $OutputPath" -ForegroundColor Green
    
    if (Test-Path $OutputPath) {
        Start-Process $OutputPath
    }
}
catch {
    Write-Error "Erreur lors de la generation du rapport: $_"
}