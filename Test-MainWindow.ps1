# Test script for Main Window (Mode Selection)

Write-Host "Test Mode Selection Window" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

function Show-MainWindow {
    param(
        [string]$FunctionToCall = ""
    )

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
            <Button Name="BtnExit" Content="Exit" Width="100" Padding="10,8" FontSize="13" FontWeight="Bold" Foreground="White" Background="#E74C3C" BorderThickness="0" Cursor="Hand" Margin="10,0,0,0"/>
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
            [System.Windows.MessageBox]::Show("Audit mode selected! The audit would start here.", "Mode Selected")
        }
        elseif ($RbRemed.IsChecked) {
            Write-Host "Selected: REMEDIATION mode" -ForegroundColor Green
            [System.Windows.MessageBox]::Show("Remediation mode selected! Opening remediation window...", "Mode Selected")
            $window.Close()
        }
    })

    $BtnExit.Add_Click({ 
        Write-Host "Exit button clicked" -ForegroundColor Yellow
        $window.Close() 
    })

    Write-Host "Opening Mode Selection Window..." -ForegroundColor Green
    Write-Host ""
    Write-Host "Instructions:" -ForegroundColor Cyan
    Write-Host "1. Select 'Audit' or 'Remediation'" -ForegroundColor Cyan
    Write-Host "2. Click 'Run' to proceed or 'Exit' to close" -ForegroundColor Cyan
    Write-Host ""

    $window.ShowDialog() | Out-Null
    
    Write-Host ""
    Write-Host "Window closed." -ForegroundColor Green
}

# Launch the main window
Show-MainWindow

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green
