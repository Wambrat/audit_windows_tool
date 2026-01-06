function Show-MainWindow {

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    Title="Mode selection"
    Height="320"
    Width="420"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    Background="#F5F5F5">

    <Grid Margin="30">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Text="Select a mode:" FontWeight="Bold" FontSize="18" Foreground="#2C3E50" Margin="0,0,0,15"/>

        <Border Grid.Row="1" Background="White" CornerRadius="8" Padding="15" Margin="0,0,0,20" BorderBrush="#E0E0E0" BorderThickness="1">
            <StackPanel>
                <RadioButton Name="RbAudit" Content="Audit" IsChecked="True" FontSize="14" Margin="0,8" Foreground="#333333"/>
                <RadioButton Name="RbRemed" Content="Remediation" FontSize="14" Margin="0,8" Foreground="#333333"/>
            </StackPanel>
        </Border>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,20,0,0">
            <Button Name="BtnRun" Content="Run" Width="100" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#27AE60" BorderThickness="0" Cursor="Hand" Margin="0,0,10,0"/>
            <Button Name="BtnExit" Content="Exit" Width="100" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#E74C3C" BorderThickness="0" Cursor="Hand"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $RbAudit = $window.FindName("RbAudit")
    $RbRemed = $window.FindName("RbRemed")
    $BtnRun  = $window.FindName("BtnRun")
    $BtnExit = $window.FindName("BtnExit")

    $BtnRun.Add_Click({
        if ($RbAudit.IsChecked) {
            Write-Host "Selected: AUDIT mode" -ForegroundColor Green
            $window.Close()
            
            try {
                $scriptPath = Join-Path $PSScriptRoot "Start-Audit.ps1"

                Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -Wait -ErrorAction Stop

                Show-AskingWindow -Message "Do you want to have a html report with results exported ?" -scriptPath "reports\ReportAuditHTML.ps1"
                Show-AskingWindow -Message "Do you want to change to REMEDIATION mode now ?" -scriptPath "Start-Remediation.ps1"
                Show-AskingWindow -Message "Do you want to have a html report with results of remediations ?" -scriptPath "reports\ReportRemediationHTML.ps1"
            }
            catch {
                Write-Host "Erreur lors de l'exécution de l'audit: $_" -ForegroundColor Red
            }
        }
        elseif ($RbRemed.IsChecked) {
            Write-Host "Selected: REMEDIATION mode" -ForegroundColor Green
            $window.Close()
            
            try {
                $scriptPath = Join-Path $PSScriptRoot "Start-Remediation.ps1"

                Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -Wait -ErrorAction Stop
                
                Show-AskingWindow -Message "Do you want to have a html report with results of remediations ?" -scriptPath "reports\ReportRemediationHTML.ps1"
            }
            catch {
                Write-Host "Erreur lors de l'exécution de la remédiation: $_" -ForegroundColor Red
            }
        }
    })

    $BtnExit.Add_Click({ $window.Close() })

    $window.ShowDialog() | Out-Null
}

function Show-AskingWindow {
    param (
        [string]$Message,
        [string]$scriptPath
    )

    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase

     $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    Title="Confirmation"
    Height="320"
    Width="420"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    Background="#F5F5F5">

    <Grid Margin="30">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Text="$Message" FontWeight="Bold" FontSize="18" Foreground="#2C3E50" Margin="0,0,0,15"/>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,20,0,0">
            <Button Name="BtnYes" Content="Yes" Width="100" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#27AE60" BorderThickness="0" Cursor="Hand" Margin="0,0,10,0"/>
            <Button Name="BtnNo" Content="No" Width="100" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#E74C3C" BorderThickness="0" Cursor="Hand"/>
        </StackPanel>
    </Grid>
</Window>
"@
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)

    $BtnYes  = $window.FindName("BtnYes")
    $BtnNo   = $window.FindName("BtnNo")

    $BtnYes.Add_Click({
        Write-Host "User chose YES" -ForegroundColor Green
        $window.Close()
        & $(Join-Path $PSScriptRoot $scriptPath)
    })

    $BtnNo.Add_Click({
        $window.Close()
    })

    $window.ShowDialog() | Out-Null
}

function ModeSelection {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    
    Show-MainWindow
}

ModeSelection
