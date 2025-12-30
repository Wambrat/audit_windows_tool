function ModeSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FunctionToCall
    )

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

        function Show-MainWindow {

        $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Mode selection"
        Height="200"
        Width="300"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize">

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Text="Select a mode:" FontWeight="Bold"/>

        <StackPanel Grid.Row="1" Margin="0,10,0,10">
            <RadioButton Name="RbAudit" Content="Audit" IsChecked="True"/>
            <RadioButton Name="RbRemed" Content="Remediation"/>
        </StackPanel>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
            <Button Name="BtnRun" Content="Run" Width="80" Margin="5"/>
            <Button Name="BtnExit" Content="Exit" Width="80" Margin="5"/>
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
                Invoke-Expression $FunctionToCall
            }
            elseif ($RbRemed.IsChecked) {
                $window.Close()
                Show-RemediationWindow
            }
        })

        $BtnExit.Add_Click({ $window.Close() })

        $window.ShowDialog() | Out-Null
    }

        function Show-RemediationWindow {

        $ofd = New-Object Microsoft.Win32.OpenFileDialog
        $ofd.Title = "Select the remediation file (XML)"
        $ofd.Filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*"

        if (-not $ofd.ShowDialog()) { return }

        try {
            $remediations = Import-Clixml -Path $ofd.FileName
        } catch {
            [System.Windows.MessageBox]::Show("Error reading XML file:`n$($_.Exception.Message)")
            return
        }

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
        Height="450"
        Width="650"
        WindowStartupLocation="CenterScreen">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Text="Select the remediations to apply:" FontWeight="Bold"/>

        <ListBox Name="LbRemed" Grid.Row="1" Margin="0,10,0,10">
            <ListBox.ItemTemplate>
                <DataTemplate>
                    <CheckBox Content="{Binding DisplayText}"
                              IsChecked="{Binding IsChecked}"/>
                </DataTemplate>
            </ListBox.ItemTemplate>
        </ListBox>

        <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <Button Name="BtnApply" Content="Apply" Width="80" Margin="5"/>
            <Button Name="BtnClose" Content="Close" Width="80" Margin="5" Grid.Column="1"/>
            <TextBox Name="TxtLog" Grid.Column="2" Margin="5" IsReadOnly="True"/>
        </Grid>
    </Grid>
</Window>
"@

        $reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
        $window = [Windows.Markup.XamlReader]::Load($reader)

        $LbRemed = $window.FindName("LbRemed")
        $BtnApply = $window.FindName("BtnApply")
        $BtnClose = $window.FindName("BtnClose")
        $TxtLog = $window.FindName("TxtLog")

        $LbRemed.ItemsSource = $items

        $BtnApply.Add_Click({
            $selected = $items | Where-Object { $_.IsChecked }

            if (-not $selected) {
                $TxtLog.Text = "No remediation selected."
                return
            }

            foreach ($entry in $selected) {
                $TxtLog.Text = "Running: $($entry.Data.Description)"
                try {
                    Invoke-RemediationCommand -Command $entry.Data.Command
                } catch {
                    [System.Windows.MessageBox]::Show(
                        "Error on '$($entry.Data.Description)':`n$($_.Exception.Message)"
                    )
                }
            }

            $TxtLog.Text = "Remediations completed."
        })

        $BtnClose.Add_Click({ $window.Close() })

        $window.ShowDialog() | Out-Null
    }

        Show-MainWindow
}
