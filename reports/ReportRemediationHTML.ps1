param(
    [Parameter(Mandatory=$false)]
    [PSObject[]]$SuccessfulResults,
    
    [Parameter(Mandatory=$false)]
    [PSObject[]]$FailedResults,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ""
)

# Fonctions Utilitaires
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return "" }
    return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
}

# Generate report timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$reportDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Determine output path
if ([string]::IsNullOrEmpty($OutputPath)) {
    $reportDir = "$(Get-Location)\reports\remediations"
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir | Out-Null
    }
    $OutputPath = "$reportDir\Remediation_Report_$reportDate.html"
}

# Get computer name
$computerName = [System.Net.Dns]::GetHostName()

# Load CSS from audit style
$styleAudit = Get-Content -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\stylesAudit.css" -Raw

# Remediation-specific CSS additions
$remediationStyles = Get-Content -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Path)\stylesRemediation.css" -Raw


# Combine styles
$fullStyle = $styleAudit + "`n" + $remediationStyles

# Count results
$successCount = if ($SuccessfulResults) { $SuccessfulResults.Count } else { 0 }
$failCount = if ($FailedResults) { $FailedResults.Count } else { 0 }
$totalCount = $successCount + $failCount
$successPercentage = if ($totalCount -gt 0) { [Math]::Round(($successCount / $totalCount) * 100, 2) } else { 0 }

# HTML report content
$htmlContent = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Remediation Report - $computerName</title>
    <style>
        $fullStyle
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Windows Security Remediation Report</h1>
            <p>Remediation Execution Summary and Results</p>
        </header>
        
        <div class="content">
            <div class="remediation-summary">
                <h2>Execution Summary</h2>
                <div class="remediation-stats">
                    <div class="stat-item">
                        <span class="stat-number">$successCount</span>
                        <span class="stat-label">Successful</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">$failCount</span>
                        <span class="stat-label">Failed</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">$totalCount</span>
                        <span class="stat-label">Total</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-number">$successPercentage%</span>
                        <span class="stat-label">Success Rate</span>
                    </div>
                </div>
            </div>
            
            <div class="system-info">
                <h2>System Information</h2>
                <div class="system-info-grid">
                    <div class="info-item">
                        <div class="info-label">Computer Name</div>
                        <div class="info-value">$(ConvertTo-HtmlSafe $computerName)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Report Date</div>
                        <div class="info-value">$timestamp</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Execution Status</div>
                        <div class="info-value"><span class="badge" style="background-color: #d4edda; color: #28a745;">COMPLETED</span></div>
                    </div>
                </div>
            </div>
"@

# Add successful remediations section
if ($successCount -gt 0) {
    $htmlContent += @"
            <h2 style="color: #28a745; margin-bottom: 20px; margin-top: 30px;">Successful Remediations ($successCount)</h2>
            <div class="vulnerabilities-list">
"@
    
    foreach ($result in $SuccessfulResults) {
        $description = ConvertTo-HtmlSafe $result.Description
        $category = ConvertTo-HtmlSafe $result.Category
        $htmlContent += @"
                <div class="remediation-item">
                    <h3> $description</h3>
                    <p><strong>Category:</strong> $category</p>
                    <p><strong>Status:</strong>Applied successfully</p>
                </div>
"@
    }
    
    $htmlContent += @"
            </div>
"@
}

# Add failed remediations section
if ($failCount -gt 0) {
    $htmlContent += @"
            <h2 style="color: #dc3545; margin-bottom: 20px; margin-top: 30px;">Failed Remediations ($failCount)</h2>
            <div class="vulnerabilities-list">
"@
    
    foreach ($result in $FailedResults) {
        $description = ConvertTo-HtmlSafe $result.Description
        $error = ConvertTo-HtmlSafe $result.Error
        $htmlContent += @"
                <div class="remediation-item error">
                    <h3>$description</h3>
                    <p><strong>Error Message:</strong> $error</p>
                    <p><strong>Status:</strong> Failed</p>
                </div>
"@
    }
    
    $htmlContent += @"
            </div>
"@
}

# Add recommendation section
if ($failCount -gt 0) {
    $htmlContent += @"
            <div class="recommendation" style="margin-top: 30px;">
                <strong>⚠️ Action Required:</strong><br>
                <p style="margin-top: 10px;">Some remediations failed during execution. Please review the error messages above and:</p>
                <ul style="margin-top: 10px; margin-left: 20px;">
                    <li>Check the system logs for more details</li>
                    <li>Ensure you have appropriate permissions</li>
                    <li>Verify system prerequisites are met</li>
                    <li>Attempt manual remediation if necessary</li>
                </ul>
            </div>
"@
} else {
    $htmlContent += @"
            <div style="background: #e8f5e9; border-left: 4px solid #28a745; padding: 20px; margin-top: 30px; border-radius: 4px;">
                <strong style="color: #28a745; font-size: 16px;">All Remediations Completed Successfully</strong>
                <p style="margin-top: 10px; color: #555;">All selected remediations have been applied to the system. The system may require a restart for some changes to take effect.</p>
            </div>
"@
}

$htmlContent += @"
        </div>
        
        <footer>
            <p>Windows Security Remediation Report | Generated on $timestamp</p>
            <p>This report was automatically generated by the Windows Audit Tool</p>
        </footer>
    </div>
</body>
</html>
"@

# Write report to file
try {
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "[OK] Remediation report generated: $OutputPath" -ForegroundColor Green
    
    # Open report in browser
    if (Test-Path $OutputPath) {
        Start-Process $OutputPath
    }
} catch {
    Write-Error "Error generating remediation report: $_"
}
