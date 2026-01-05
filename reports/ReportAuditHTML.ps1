if (-not (Test-Path -Path "$(Get-Location)\reports")) {
    New-Item -ItemType Directory -Path "$(Get-Location)\reports" | Out-Null
}

$OutputPath = "$(Get-Location)\reports\audits\Audit_Report_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"

# Configuration
$ErrorActionPreference = "Stop"

$jsonFiles = Get-ChildItem -Path "$(Get-Location)\auditResults" -Filter "*.json"
$latestJsonFile = $jsonFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$AuditResults = Get-Content -Path $latestJsonFile.FullName -Raw | ConvertFrom-Json

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
                    
                    if ($itemValue.status -eq "PASS") {
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

function Get-StatusInfos {
    param([string]$status)
    switch ($status) {
        "FAIL" { return "#dc3545", "NON CONFORME", "#f8d7da" }
        "PASS" { return "#28a745", "CONFORME", "#d4edda" }
        "WARNING" { return "#ffc107", "PARTIELLEMENT CONFORME", "#fff3cd" }
        default { return "#6c757d", "INCONNU", "#e2e3e5" }
    }
}

function Get-StatusBadge {
    param([string]$status)
    $color, $text, $bgColor = Get-StatusInfos $status
    return "<span class='badge' style='background-color: $bgColor; color: $color;'>$text</span>"
}

function Get-AutomatisableBadge {
    param([string]$automatable)
    
    $isAutomatable = if ($automatable -eq "True" -or $automatable -eq "true" -or $automatable -eq 1) { $true } else { $false }
    $bgColor = if ($isAutomatable) { "#d1ecf1" } else { "#fff3cd" }
    $color = if ($isAutomatable) { "#0c5460" } else { "#856404" }
    $text = if ($isAutomatable) { "Automatique" } else { "Manuel" }
    
    return "<span class='badge' style='background-color: $bgColor; color: $color;'>$text</span>"
}

$style = Get-Content -Path "$(Split-Path -Parent $PSCommandPath)\stylesAudit.css" -Raw -Encoding UTF8
$script = Get-Content -Path "$(Split-Path -Parent $PSCommandPath)\scriptAudit.js" -Raw -Encoding UTF8

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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Audit Report - $computerName</title>
</head>
<body>
    <div class="container">
        <header>
            <div style="position: absolute; top: 20px; right: 30px;">
                <select id="languageSelector" style="padding: 10px 16px; border-radius: 8px; border: 2px solid #3483ff; background: linear-gradient(135deg, #ffffff 0%, #f9f9f9 100%); color: #333; font-weight: 600; cursor: pointer; transition: all 0.3s ease; font-size: 14px; box-shadow: 0 4px 12px rgba(52, 131, 255, 0.2); min-width: 140px;" onchange="changeLanguage(this.value)">
                    <option value="en">English</option>
                    <option value="fr" selected>Fran&ccedil;ais</option>
                </select>
            </div>
            <p style="margin: 0 0 10px 0; font-size: 16px; font-weight: 300; opacity: 0.95;">JadusAudit</p>
            <h1 data-en="Windows Security Audit Report - " data-fr="Rapport d&apos;Audit de S&eacute;curit&eacute; Windows - ">Rapport d&apos;Audit de S&eacute;curit&eacute; Windows - $computerName</h1>
            <p data-en="Complete System Security Audit" data-fr="Audit Complet de la S&eacute;curit&eacute; du Syst&egrave;me">Audit Complet de la S&eacute;curit&eacute; du Syst&egrave;me</p>
        </header>
        
        <div class="content">
            <div class="score-section">
                <h2 style="margin-bottom: 20px;" data-en="Security Score" data-fr="Score de S&eacute;curit&eacute;">Score de S&eacute;curit&eacute;</h2>
                <div class="score-circle">
                    <div class="score-number">$($scoreInfo.Score)</div>
                    <div class="score-total">/$($scoreInfo.Total)</div>
                </div>
                <div class="score-percentage">$($scoreInfo.Percentage)%</div>
                <p style="margin-top: 15px;" data-en="Based on the number of valid security controls" data-fr="En fonction du nombre de contr&ocirc;les de s&eacute;curit&eacute; valides">En fonction du nombre de contr&ocirc;les de s&eacute;curit&eacute; valides</p>
            </div>
            
            <div class="system-info">
                <h2 data-en="System Information" data-fr="Informations Syst&egrave;me">Informations Syst&egrave;me</h2>
                <div class="system-info-grid">
                    <div class="info-item">
                        <div class="info-label" data-en="Computer Name" data-fr="Nom de l&apos;Ordinateur">Nom de l&apos;Ordinateur</div>
                        <div class="info-value">$(ConvertTo-HtmlSafe $computerName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label" data-en="Operating System" data-fr="Syst&egrave;me d&apos;Exploitation">Syst&egrave;me d&apos;Exploitation</div>
                        <div class="info-value">$(ConvertTo-HtmlSafe $osInfo)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label" data-en="Report Date" data-fr="Date du Rapport">Date du Rapport</div>
                        <div class="info-value">$timestamp</div>
                    </div>
                </div>
            </div>

            
            <div class="search-section">
                <h2 style="color: #3483ff; margin-bottom: 20px" data-en="Vulnerabilities Summary" data-fr="R&eacute;sum&eacute; des Vuln&eacute;rabilit&eacute;s">R&eacute;sum&eacute; des Vuln&eacute;rabilit&eacute;s</h2>
                <input type="text" class="search-box" id="searchInput" placeholder="Rechercher une vuln&eacute;rabilit&eacute;..." data-en-placeholder="Search for a vulnerability..." data-fr-placeholder="Rechercher une vuln&eacute;rabilit&eacute;...">
            </div>
            
            <div class="filter-section">
                <div class="filter-group">
                    <strong data-en="Vulnerabilities:" data-fr="Vuln&eacute;rabilit&eacute;s:">Vuln&eacute;rabilit&eacute;s:</strong>
                    <button class="filter-btn unknown-btn" data-filter="status" data-value="unknown" data-en="Unknown" data-fr="Inconnu">Inconnu</button>
                    <button class="filter-btn bad-btn" data-filter="status" data-value="bad" data-en="Non Compliant" data-fr="Non Conforme">Non Conforme</button>
                    <button class="filter-btn warning-btn" data-filter="status" data-value="warning" data-en="Semi-Compliant" data-fr="Partiellement Conforme">Partiellement Conforme</button>
                    <button class="filter-btn good-btn" data-filter="status" data-value="good" data-en="Compliant" data-fr="Conforme">Conforme</button>
                </div>
                <div class="filter-group">
                    <strong data-en="Remediations:" data-fr="R&eacute;m&eacute;diations:">R&eacute;m&eacute;diations:</strong>
                    <button class="filter-btn auto-btn" data-filter="automation" data-value="auto" data-en="Automatic" data-fr="Automatique">Automatique</button>
                    <button class="filter-btn manual-btn" data-filter="automation" data-value="manual" data-en="Manual" data-fr="Manuel">Manuel</button>
                </div>
            </div>
            
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
            # Value contains statut, automatisable, recommendations : list, commentaires et x autres infos a placer dans les détails
			
            $statusBadge = Get-StatusBadge -status $itemValue.status
            $automatisableBadge = Get-AutomatisableBadge -Automatable $itemValue.automatable
            
            $htmlContent += @"
                <div class="vulnerability-item $($itemValue.status.ToLower())" data-automation="$($itemValue.automatable)" onclick="toggleDetails(this)">
                    <h3>
                        <span>$itemName</span>
                        <span class="status">$statusBadge $automatisableBadge</span>
                    </h3>
                    <div class="details" style="display: none;">
                        <div class="details-label">Category:</div>
                        <div class="details-content">$categoryName</div>
                        <div class="details-label">Comments:</div>
                        <div class="details-content">$($itemValue.comments)</div>
"@
            foreach ($recommendation in $itemValue.recommendations) {
                $htmlContent += @"
                            <div class="recommendation" style="display: $(if ($recommendation -and $recommendation -ne "None") { "block" } else { "none" });">
                                <strong>Recommandation:</strong><br>
                                $recommendation
                            </div>
"@
            }

            # rajouter les details supplementaires dans un dropdown discret
            $additionalDetails = @()
            foreach ($prop in $itemValue.PSObject.Properties) {
                if ($prop.Name -notin @("status", "automatable", "comments", "recommendations")) {
                    $detailLabel = ConvertTo-HtmlSafe $prop.Name
                    $detailContent = ConvertTo-HtmlSafe $prop.Value
                    $additionalDetails += @"
                        <div class="additional-detail">
                            <span class="detail-label">${detailLabel}:</span>
                            <span class="detail-value">$detailContent</span>
                        </div>
"@
                }
            }
            
            if ($additionalDetails.Count -gt 0) {
                $htmlContent += @"
                        <div class="additional-details-section">
                            <button class="details-toggle" onclick="event.stopPropagation(); toggleAdditionalDetails(this)">
                                <span class="toggle-icon">></span> Additional Details
                            </button>
                            <div class="additional-details-content" style="display: none;">
$($additionalDetails -join "`n")
                            </div>
                        </div>
"@
            }


            $htmlContent += @"
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
            <p data-en="You can find the detailed remediation informations in the repository : audit_windows_tool\xmls" data-fr="Vous pouvez trouver les informations de r&eacute;m&eacute;diation d&eacute;taill&eacute;es dans le r&eacute;pertoire : audit_windows_tool\xmls">Vous pouvez trouver les informations de r&eacute;m&eacute;diation d&eacute;taill&eacute;es dans le r&eacute;pertoire : audit_windows_tool\xmls</p>
            <p data-en="This audit provides an overview of security configurations. For more details, consult the system logs." data-fr="Cet audit fournit un aper&ccedil;u des configurations de s&eacute;curit&eacute;. Pour plus de d&eacute;tails, consultez les journaux syst&egrave;me.">Cet audit fournit un aper&ccedil;u des configurations de s&eacute;curit&eacute;. Pour plus de d&eacute;tails, consultez les journaux syst&egrave;me.</p>
            <p data-en="Report generated by JadusAudit from ZakelElectonics | " data-fr="Rapport g&eacute;n&eacute;r&eacute; par JadusAudit de ZakelElectonics | ">Rapport g&eacute;n&eacute;r&eacute; par JadusAudit de ZakelElectonics | $timestamp</p>
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