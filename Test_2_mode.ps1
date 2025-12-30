Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing


function Start-Audit {
    [System.Windows.Forms.MessageBox]::Show("AUDIT mode started")

    $test = Get-SMBAudit
    $test.Xml | Export-Clixml -Path C:\Temp\test.xml

    [System.Windows.Forms.MessageBox]::Show(
    "Audit completed successfully.",
    "Audit status",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
    )

}

function Invoke-RemediationCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Command
    )

    Invoke-Expression $Command
}


function Show-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Mode selection"
    $form.Size = New-Object System.Drawing.Size(320,190)
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Select a mode:"
    $label.Location = New-Object System.Drawing.Point(20,20)
    $label.AutoSize = $true
    $form.Controls.Add($label)

    $rbAudit = New-Object System.Windows.Forms.RadioButton
    $rbAudit.Text = "Audit"
    $rbAudit.Location = New-Object System.Drawing.Point(40,50)
    $rbAudit.AutoSize = $true
    $rbAudit.Checked = $true
    $form.Controls.Add($rbAudit)

    $rbRemed = New-Object System.Windows.Forms.RadioButton
    $rbRemed.Text = "Remediation"
    $rbRemed.Location = New-Object System.Drawing.Point(40,75)
    $rbRemed.AutoSize = $true
    $form.Controls.Add($rbRemed)

    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = "Run"
    $btnRun.Location = New-Object System.Drawing.Point(40,115)
    $btnRun.Size = New-Object System.Drawing.Size(80,25)
    $form.Controls.Add($btnRun)

    $btnQuit = New-Object System.Windows.Forms.Button
    $btnQuit.Text = "Exit"
    $btnQuit.Location = New-Object System.Drawing.Point(150,115)
    $btnQuit.Size = New-Object System.Drawing.Size(80,25)
    $form.Controls.Add($btnQuit)

    $btnRun.Add_Click({
        if ($rbAudit.Checked) {
            Start-Audit
        }
        elseif ($rbRemed.Checked) {
            $form.Hide()
            Show-RemediationForm
        }
    })

    $btnQuit.Add_Click({ $form.Close() })

    [void]$form.ShowDialog()
}


function Show-RemediationForm {

    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = "Select the remediation file (XML)"
    $ofd.Filter = "XML files|*.xml|All files|*.*"
    if ($ofd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    try {
        $remediations = Import-Clixml -Path $ofd.FileName
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error reading XML file: $($_.Exception.Message)")
        return
    }

    $displayItems = foreach ($item in $remediations) {
        $displayText = if ($item.Category) {
            "[{0}] {1}" -f $item.Category, $item.Description
        } else {
            $item.Description
        }

        [pscustomobject]@{
            DisplayText = $displayText
            Data        = $item
        }
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Remediations"
    $form.Size = New-Object System.Drawing.Size(600,400)
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Select the remediations to apply:"
    $label.Location = New-Object System.Drawing.Point(10,10)
    $label.AutoSize = $true
    $form.Controls.Add($label)

    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.Location = New-Object System.Drawing.Point(10,35)
    $clb.Size = New-Object System.Drawing.Size(560,260)
    $clb.CheckOnClick = $true
    $form.Controls.Add($clb)

    $clb.HorizontalScrollbar = $true              
    $clb.IntegralHeight = $true
    $form.Controls.Add($clb)

    foreach ($displayItem in $displayItems) {
        [void]$clb.Items.Add($displayItem, $false)
    }
    $clb.DisplayMember = 'DisplayText'

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply"
    $btnApply.Location = New-Object System.Drawing.Point(10,310)
    $btnApply.Size = New-Object System.Drawing.Size(80,25)
    $form.Controls.Add($btnApply)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Location = New-Object System.Drawing.Point(110,310)
    $btnClose.Size = New-Object System.Drawing.Size(80,25)
    $form.Controls.Add($btnClose)

    $txtLog = New-Object System.Windows.Forms.TextBox
    $txtLog.Location = New-Object System.Drawing.Point(210,310)
    $txtLog.Size = New-Object System.Drawing.Size(360,25)
    $txtLog.ReadOnly = $true
    $form.Controls.Add($txtLog)

    $btnApply.Add_Click({
        if ($clb.CheckedItems.Count -eq 0) {
            $txtLog.Text = "No remediation selected."
            return
        }

        foreach ($checkedWrapper in $clb.CheckedItems) {
            $rem = $checkedWrapper.Data
            $txtLog.Text = "Running: $($rem.Description)"
            try {
                Invoke-RemediationCommand -Command $rem.Command
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error on '$($rem.Description)': $($_.Exception.Message)")
            }
        }

        $txtLog.Text = "Remediations completed."
    })

    $btnClose.Add_Click({ $form.Close() })

    [void]$form.ShowDialog()
}

Show-MainForm
