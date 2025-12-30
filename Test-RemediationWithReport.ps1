# Test script for Remediation Window with success/failure scenarios

Write-Host "Test Remediation Window with Report" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

function Invoke-RemediationCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Command
    )

    Invoke-Expression $Command
}

# Create sample remediation objects with success and failure scenarios
$remediations = @(
    [PSCustomObject]@{
        Category = "Firewall"
        Description = "Enable Windows Defender Firewall"
        Command = 'Write-Host "`u{2713} Enabling Windows Defender Firewall..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "Firewall"
        Description = "Enable Domain Profile"
        Command = 'Write-Host "`u{2713} Enabling Domain Profile..." -ForegroundColor Green; throw "Permission denied: Unable to modify firewall settings"; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "BitLocker"
        Description = "Enable BitLocker encryption"
        Command = 'Write-Host "`u{2713} Enabling BitLocker..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "UAC"
        Description = "Enable User Account Control"
        Command = 'Write-Host "`u{2713} Enabling UAC..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "Updates"
        Description = "Configure Windows Updates to automatic"
        Command = 'Write-Host "`u{2713} Configuring Windows Updates..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "SMB"
        Description = "Disable SMB v1"
        Command = 'Write-Host "`u{2713} Disabling SMB v1..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "Network"
        Description = "Disable Network Discovery"
        Command = 'Write-Host "`u{2713} Disabling Network Discovery..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "RDP"
        Description = "Enable Network Level Authentication for RDP"
        Command = 'Write-Host "`u{2713} Enabling NLA for RDP..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "Defender"
        Description = "Enable Windows Defender Real-time Protection"
        Command = 'Write-Host "`u{2713} Enabling Defender Real-time Protection..." -ForegroundColor Green; Start-Sleep -Seconds 1'
    },
    [PSCustomObject]@{
        Category = "CredentialGuard"
        Description = "Enable Credential Guard"
        Command = 'Write-Host "`u{2713} Enabling Credential Guard..."; Write-Host "Note: Requires reboot" -ForegroundColor Yellow; Start-Sleep -Seconds 1'
    }
)

Write-Host "Test data prepared with 10 remediations (all will succeed)." -ForegroundColor Green
Write-Host ""
Write-Host "Launching Remediation Window with test data..." -ForegroundColor Cyan
Write-Host "After running remediation, check if report opens automatically!" -ForegroundColor Yellow
Write-Host ""

# Create ObservableCollection
$items = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    foreach ($item in $remediations) {
        $text = if ($item.Category) {
            "[{0}] {1}" -f $item.Category, $item.Description
        } else {
            $item.Description
        }

        $items.Add(
            [pscustomobject]@{
                DisplayText = $text
                Data        = $item
                IsChecked   = $false
            }
        )
    }


    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Remediations"
        Height="520"
        Width="750"
        WindowStartupLocation="CenterScreen"
        Background="#F5F5F5">

    <Grid Margin="25">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Grid Grid.Row="0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Text="Select the remediations to apply:" FontWeight="Bold" FontSize="16" Foreground="#2C3E50"/>
            <Button Name="BtnSelectAll" Content="Select All" Grid.Column="1" Width="90" Padding="8,6" FontSize="12" FontWeight="Bold" Foreground="White" Background="#3498DB" BorderThickness="0" Cursor="Hand"/>
        </Grid>

        <Border Grid.Row="1" Background="White" CornerRadius="8" Padding="12" Margin="0,0,0,20" BorderBrush="#E0E0E0" BorderThickness="1">
            <ListBox Name="LbRemed" Background="White" BorderThickness="0">
                <ListBox.ItemTemplate>
                    <DataTemplate>
                        <CheckBox Content="{Binding DisplayText}"
                                  IsChecked="{Binding IsChecked}"
                                  FontSize="13"
                                  Padding="5"
                                  Foreground="#333333"
                                  VerticalAlignment="Center"
                                  VerticalContentAlignment="Center"/>
                    </DataTemplate>
                </ListBox.ItemTemplate>
            </ListBox>
        </Border>

        <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <Button Name="BtnApply" Content="Apply" Width="90" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#27AE60" BorderThickness="0" Cursor="Hand" Margin="0,0,10,0"/>
            <Border Grid.Column="2" Background="White" CornerRadius="4" BorderBrush="#E0E0E0" BorderThickness="1" Padding="8">
                <TextBox Name="TxtLog" Background="White" BorderThickness="0" IsReadOnly="True" FontSize="12" Foreground="#555555"/>
            </Border>
        </Grid>

        <StackPanel Grid.Row="3" HorizontalAlignment="Center" Margin="0,15,0,0">
            <Button Name="BtnGenerateReport" Content="Generate Report" Width="150" Padding="12,10" FontSize="13" FontWeight="Bold" Foreground="White" Background="#3498DB" BorderThickness="0" Cursor="Hand" Visibility="Collapsed"/>
        </StackPanel>

    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $LbRemed = $window.FindName("LbRemed")
    $BtnSelectAll = $window.FindName("BtnSelectAll")
    $BtnApply = $window.FindName("BtnApply")
    $BtnGenerateReport = $window.FindName("BtnGenerateReport")
    $TxtLog = $window.FindName("TxtLog")

    $LbRemed.ItemsSource = $items
    
    # Flag pour éviter les clics multiples
    $isRunning = $false
    
    # Variables pour tracker les résultats
    $successfulRemediations = @()
    $failedRemediations = @()
    
    # Toggle Select All / Deselect All
    $BtnSelectAll.Add_Click({
        $allChecked = $items | Where-Object { $_.IsChecked -eq $true }
        
        if ($allChecked.Count -eq $items.Count) {
            # All are selected, so deselect all
            foreach ($item in $items) {
                $item.IsChecked = $false
            }
            $BtnSelectAll.Content = "Select All"
        } else {
            # Some or none are selected, so select all
            foreach ($item in $items) {
                $item.IsChecked = $true
            }
            $BtnSelectAll.Content = "Deselect All"
        }
        
        # Refresh the ListBox display
        $LbRemed.Items.Refresh()
    })

    $BtnApply.Add_Click({
        # Ignorer si une remédiation est déjà en cours
        if ($isRunning) {
            return
        }
        
        $selected = $items | Where-Object { $_.IsChecked }

        if (-not $selected) {
            $TxtLog.Text = "No remediation selected."
            return
        }

        # Marquer comme en cours
        $isRunning = $true
        
        # Désactiver tous les contrôles
        $BtnApply.IsEnabled = $false
        $BtnSelectAll.IsEnabled = $false
        $LbRemed.IsEnabled = $false
        $BtnApply.Opacity = 0.5
        $TxtLog.Text = "Running remediations... Please wait."

        # Réinitialiser les listes de résultats (sans créer de nouvelles variables)
        $script:failedRemediations = @()
        $script:successfulRemediations = @()
        $successCount = 0

        foreach ($entry in $selected) {
            $TxtLog.Text = "Running: $($entry.Data.Description)"
            try {
                Invoke-RemediationCommand -Command $entry.Data.Command
                $successCount++
                $script:successfulRemediations += [PSCustomObject]@{
                    Category = $entry.Data.Category
                    Description = $entry.Data.Description
                    Command = $entry.Data.Command
                    Status = "Success"
                }
            } catch {
                $script:failedRemediations += [PSCustomObject]@{
                    Description = $entry.Data.Description
                    Error = $_.Exception.Message
                }
                
                # Log de l'erreur
                $logDir = Join-Path $env:TEMP "AuditWindowsTool_Logs"
                if (-not (Test-Path $logDir)) {
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }
                $logFile = Join-Path $logDir "remediation_errors_$(Get-Date -Format 'yyyyMMdd').log"
                $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | ERROR | $($entry.Data.Description) | $($_.Exception.Message)"
                Add-Content -Path $logFile -Value $logEntry
            }
        }

        # Réactiver les contrôles
        $BtnApply.IsEnabled = $true
        $BtnSelectAll.IsEnabled = $true
        $LbRemed.IsEnabled = $true
        $BtnApply.Opacity = 1

        # Si toutes les remédiation ont réussi
        if ($script:failedRemediations.Count -eq 0) {
            $TxtLog.Text = "All remediations completed successfully!"
            [System.Windows.MessageBox]::Show("All $successCount remediation(s) completed successfully!", "Success")
            
            # Lancer le script de rapport avec les remediations réussies et échouées
            $reportScriptPath = Join-Path $PSScriptRoot "reports\ReportRemediationHTML.ps1"
            if (Test-Path $reportScriptPath) {
                & $reportScriptPath -SuccessfulResults $script:successfulRemediations -FailedResults $script:failedRemediations
            } else {
                Write-Host "Remediation report script not found at: $reportScriptPath" -ForegroundColor Yellow
            }

            $window.Close()
        } else {
            # Afficher uniquement les remédiation qui ont échoué
            $TxtLog.Text = "Remediations completed with $($script:failedRemediations.Count) error(s). See log for details."
            
            # Montrer le bouton de génération de rapport
            $BtnGenerateReport.Visibility = "Visible"

            # enlever les bouttons pour les remédiations réussies de la liste
            foreach ($success in $selected) {
                if (-not ($script:failedRemediations | Where-Object { $_.Description -eq $success.Data.Description })) {
                    $items.Remove($success)
                }
            }

            # demander à l'utilisateur de consulter le log
            [System.Windows.MessageBox]::Show("Some remediations failed. Please check the log file and see the updated remediation list.", "Errors Occurred")

        }
        
        # Marquer comme fini
        $isRunning = $false
    })

    $BtnGenerateReport.Add_Click({
        Write-Host "BtnGenerateReport clicked - Successful: $($script:successfulRemediations.Count), Failed: $($script:failedRemediations.Count)" -ForegroundColor Yellow

        $reportScriptPath = Join-Path $PSScriptRoot "reports\ReportRemediationHTML.ps1"
        Write-Host "Report script path: $reportScriptPath" -ForegroundColor Yellow
        if (Test-Path $reportScriptPath) {
            Write-Host "Report script found" -ForegroundColor Green
            if ($script:successfulRemediations.Count -gt 0 -or $script:failedRemediations.Count -gt 0) {
                Write-Host "Data found - launching report" -ForegroundColor Green
                & $reportScriptPath -SuccessfulResults $script:successfulRemediations -FailedResults $script:failedRemediations

                $window.Close()
            } else {
                Write-Host "No data available" -ForegroundColor Red
                [System.Windows.MessageBox]::Show("No remediation data available.", "No Data")
            }
        } else {
            Write-Host "Remediation report script not found at: $reportScriptPath" -ForegroundColor Red
        }
    })

Write-Host "Instructions:" -ForegroundColor Cyan
Write-Host "1. Click 'Select All' to select all remediations" -ForegroundColor Cyan
Write-Host "2. Click 'Apply' to run them" -ForegroundColor Cyan
Write-Host "3. Since all remediations succeed, a report should open" -ForegroundColor Cyan
Write-Host ""

$window.ShowDialog() | Out-Null

Write-Host ""
Write-Host "Remediation window closed." -ForegroundColor Green
Write-Host "Test completed!" -ForegroundColor Green
