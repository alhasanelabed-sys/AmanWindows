#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Console,
    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'أمان Windows يعمل على Windows 10 أو 11 فقط.'
    exit 1
}

$modulePath = Join-Path $PSScriptRoot 'Guard.Core.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop
. (Join-Path $PSScriptRoot 'Report.ps1')

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'AmanWindows\Reports'
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$script:EntryPointPath = [System.IO.Path]::GetFullPath($PSCommandPath)

if ($Console) {
    try {
        $report = Get-GuardReport
        $paths = Export-GuardReport -Report $report -Directory $OutputDirectory
        Write-Output 'اكتمل الفحص المحلي. هذه النتائج ليست ضمانًا لسلامة الجهاز أو دليلًا على هوية مهاجم.'
        foreach ($finding in @($report.Findings)) {
            Write-Output ('[{0}] {1}: {2}' -f $finding.Severity, $finding.Title, $finding.Detail)
        }
        Write-Output ('HTML: ' + $paths.HtmlPath)
        Write-Output ('JSON: ' + $paths.JsonPath)
        exit 0
    } catch {
        Write-Error ('تعذر إكمال الفحص أو حفظ التقرير: ' + $_.Exception.Message)
        exit 1
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:LatestReport = $null
$script:LatestPaths = $null
$script:SectionEntries = @()
$script:PendingTask = $null
$script:Busy = $false
$script:Privileged = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Actions = @(Get-GuardActions)
$script:BusyControls = New-Object 'System.Collections.Generic.List[System.Windows.Forms.Control]'

function Show-GuardMessage {
    param([string]$Message, [string]$Title = 'أمان Windows', [switch]$Failure)
    $icon = if ($Failure) { [System.Windows.Forms.MessageBoxIcon]::Warning } else { [System.Windows.Forms.MessageBoxIcon]::Information }
    [void][System.Windows.Forms.MessageBox]::Show($form, $Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::RtlReading)
}

function Confirm-GuardOperation {
    param([string]$Message)
    $answer = [System.Windows.Forms.MessageBox]::Show($form, $Message, 'تأكيد الإجراء', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question, [System.Windows.Forms.MessageBoxDefaultButton]::Button2, [System.Windows.Forms.MessageBoxOptions]::RtlReading)
    return $answer -eq [System.Windows.Forms.DialogResult]::Yes
}

function Set-GuardBusy {
    param([bool]$Value, [string]$Message)
    $script:Busy = $Value
    foreach ($control in $script:BusyControls) { $control.Enabled = -not $Value }
    if (-not $Value) {
        $reportButton.Enabled = $null -ne $script:LatestPaths
        $folderButton.Enabled = $null -ne $script:LatestPaths
        $adminButton.Enabled = -not $script:Privileged
        $applyButton.Enabled = $script:Privileged -and ($actionChoice.SelectedIndex -ge 0)
    }
    $statusLabel.Text = $Message
    $progress.Visible = $Value
}

function New-GuardButton {
    param([string]$Text, [int]$Width = 125)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Width = $Width
    $button.Height = 34
    $button.Margin = New-Object System.Windows.Forms.Padding(4)
    [void]$script:BusyControls.Add($button)
    return $button
}

function Start-GuardWork {
    param([ValidateSet('Scan', 'Action', 'DefenderScan', 'UpdateSignatures')][string]$Operation, [string]$Argument, [string]$Description)
    if ($script:Busy) { return }
    Set-GuardBusy -Value $true -Message $Description
    $runspace = $null
    $powerShell = $null
    try {
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $runspace.ApartmentState = 'STA'
        $runspace.ThreadOptions = 'ReuseThread'
        $runspace.Open()
        $powerShell = [System.Management.Automation.PowerShell]::Create()
        $powerShell.Runspace = $runspace
        [void]$powerShell.AddScript(@'
param($modulePath, $operation, $argument, $receiptDirectory)
$ErrorActionPreference = 'Stop'
Import-Module -Name $modulePath -Force -ErrorAction Stop
switch ($operation) {
    'Scan' { Get-GuardReport }
    'Action' { Invoke-GuardAction -ActionId $argument -ReceiptDirectory $receiptDirectory -Confirm:$false }
    'DefenderScan' { Invoke-GuardDefenderScan -ScanType $argument }
    'UpdateSignatures' { Update-GuardDefenderSignatures }
    default { throw 'Unsupported operation.' }
}
'@)
        [void]$powerShell.AddArgument($modulePath)
        [void]$powerShell.AddArgument($Operation)
        [void]$powerShell.AddArgument($Argument)
        [void]$powerShell.AddArgument((Join-Path $OutputDirectory 'Receipts'))
        $handle = $powerShell.BeginInvoke()
        $script:PendingTask = [pscustomobject]@{ PowerShell = $powerShell; Runspace = $runspace; Handle = $handle; Operation = $Operation }
    } catch {
        if ($null -ne $powerShell) { $powerShell.Dispose() }
        if ($null -ne $runspace) { $runspace.Dispose() }
        Set-GuardBusy -Value $false -Message 'تعذر بدء العملية.'
        Show-GuardMessage -Message $_.Exception.Message -Failure
    }
}

function Show-GuardSection {
    if ($sectionChoice.SelectedIndex -lt 0) { return }
    $entry = $script:SectionEntries[$sectionChoice.SelectedIndex]
    $section = $entry.Section
    $availability = if ($section.Available) { 'الفحص متاح' } else { 'الفحص غير متاح أو غير مكتمل' }
    $text = $entry.Name + [Environment]::NewLine + $availability
    if (-not [string]::IsNullOrWhiteSpace([string]$section.Error)) { $text += [Environment]::NewLine + 'السبب: ' + $section.Error }
    $text += [Environment]::NewLine + [Environment]::NewLine + (ConvertTo-Json -InputObject $section.Data -Depth 40)
    $evidenceText.Text = $text
}

function Show-GuardReport {
    param([object]$Report)
    $script:LatestReport = $Report
    $findingsGrid.Rows.Clear()
    $labels = @{ High = 'عالية'; Medium = 'متوسطة'; Info = 'معلومات'; Unknown = 'غير محسومة' }
    foreach ($finding in @($Report.Findings)) {
        $severity = [string]$finding.Severity
        $label = if ($labels.ContainsKey($severity)) { $labels[$severity] } else { $severity }
        $index = $findingsGrid.Rows.Add($label, [string]$finding.Title, [string]$finding.Detail)
        $findingsGrid.Rows[$index].Tag = $finding
        if ($severity -eq 'High') { $findingsGrid.Rows[$index].Cells[0].Style.ForeColor = [Drawing.Color]::DarkRed }
        if ($severity -eq 'Medium') { $findingsGrid.Rows[$index].Cells[0].Style.ForeColor = [Drawing.Color]::SaddleBrown }
    }
    $script:SectionEntries = @(Get-GuardSectionEntries -Sections $Report.Sections)
    $sectionChoice.Items.Clear()
    foreach ($entry in $script:SectionEntries) {
        $label = $entry.Name
        if (-not $entry.Section.Available) { $label += ' — غير مكتمل' }
        [void]$sectionChoice.Items.Add($label)
    }
    if ($sectionChoice.Items.Count -gt 0) { $sectionChoice.SelectedIndex = 0 }
    $high = @($Report.Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium = @($Report.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $unavailable = @($script:SectionEntries | Where-Object { -not $_.Section.Available }).Count
    $summaryLabel.Text = 'نتائج عالية: ' + $high + '   |   متوسطة: ' + $medium + '   |   فحوص غير مكتملة: ' + $unavailable + '   |   مسؤول: ' + $(if ($Report.IsAdmin) { 'نعم' } else { 'لا' })
    if ($findingsGrid.Rows.Count -eq 0) { $findingDetail.Text = 'لم تُسجل نتائج في الفحوص المتاحة. راجع تبويب الأدلة للتأكد من توافر الفحوص؛ هذا لا يضمن سلامة الجهاز.' }
    $script:LatestPaths = $null
    try {
        $script:LatestPaths = Export-GuardReport -Report $Report -Directory $OutputDirectory
        Set-GuardBusy -Value $false -Message ('اكتمل الفحص وحُفظ التقرير المحلي. وقت الفحص (UTC): ' + $Report.TimestampUtc)
    } catch {
        Set-GuardBusy -Value $false -Message 'اكتمل الفحص، لكن تعذر حفظ التقرير.'
        Show-GuardMessage -Message ('يمكنك مراجعة النتائج هنا، لكن لم يُحفظ التقرير: ' + $_.Exception.Message) -Failure
    }
}

function ConvertTo-GuardNativeArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    $escaped = [Regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [Regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'أمان Windows — فحص وحماية محلية'
$form.Size = New-Object System.Drawing.Size(1160, 850)
$form.MinimumSize = New-Object System.Drawing.Size(940, 720)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$form.RightToLeft = 'Yes'
$form.RightToLeftLayout = $true
$form.BackColor = [Drawing.Color]::FromArgb(244, 247, 251)

$layout = New-Object System.Windows.Forms.TableLayoutPanel
$layout.Dock = 'Fill'
$layout.Padding = New-Object System.Windows.Forms.Padding(14)
$layout.ColumnCount = 1
$layout.RowCount = 7
foreach ($height in @(58, 62, 44, 84, 32)) { [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $height))) }
[void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 56)))
$form.Controls.Add($layout)

$heading = New-Object System.Windows.Forms.Label
$heading.Dock = 'Fill'
$heading.Font = New-Object System.Drawing.Font('Segoe UI', 15, [Drawing.FontStyle]::Bold)
$heading.Text = 'أمان Windows' + [Environment]::NewLine + 'فحص إعدادات الحماية ومراجعة مؤشرات أمنية محلية'
$heading.AutoEllipsis = $true
$layout.Controls.Add($heading, 0, 0)

$notice = New-Object System.Windows.Forms.Label
$notice.Dock = 'Fill'
$notice.BackColor = [Drawing.Color]::FromArgb(255, 241, 213)
$notice.Padding = New-Object System.Windows.Forms.Padding(8)
$notice.Text = 'عناوين IP والمنافذ والسجلات لا تثبت اختراقًا أو هوية مهاجم. الفحص قد يكون جزئيًا. تُحفظ التقارير محليًا، والإصلاحات تحتاج تأكيدك؛ بعض الإجراءات تتطلب صلاحيات المسؤول.'
$layout.Controls.Add($notice, 0, 1)

$toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
$toolbar.Dock = 'Fill'
$toolbar.FlowDirection = 'RightToLeft'
$toolbar.WrapContents = $false
$scanButton = New-GuardButton 'فحص الحالة' 116
$reportButton = New-GuardButton 'فتح التقرير' 116
$folderButton = New-GuardButton 'مجلد التقارير' 128
$adminButton = New-GuardButton 'تشغيل كمسؤول' 145
$securityButton = New-GuardButton 'أمان Windows' 134
$updateButton = New-GuardButton 'تحديث Windows' 140
foreach ($button in @($scanButton, $reportButton, $folderButton, $adminButton, $securityButton, $updateButton)) { $toolbar.Controls.Add($button) }
$layout.Controls.Add($toolbar, 0, 2)

$actionsLayout = New-Object System.Windows.Forms.TableLayoutPanel
$actionsLayout.Dock = 'Fill'
$actionsLayout.ColumnCount = 1
$actionsLayout.RowCount = 2
[void]$actionsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 44)))
[void]$actionsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$actionsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$actionsPanel.Dock = 'Fill'
$actionsPanel.FlowDirection = 'RightToLeft'
$actionsPanel.WrapContents = $false
$actionChoice = New-Object System.Windows.Forms.ComboBox
$actionChoice.DropDownStyle = 'DropDownList'
$actionChoice.Width = 260
$actionChoice.Margin = New-Object System.Windows.Forms.Padding(4, 7, 4, 4)
$actionChoice.DisplayMember = 'Title'
foreach ($action in $script:Actions) { [void]$actionChoice.Items.Add($action) }
$actionChoice.SelectedIndex = -1
[void]$script:BusyControls.Add($actionChoice)
$applyButton = New-GuardButton 'تطبيق الإجراء' 128
$quickButton = New-GuardButton 'Defender سريع' 130
$fullButton = New-GuardButton 'Defender كامل' 132
$signaturesButton = New-GuardButton 'تحديث تعريفات Defender' 195
foreach ($control in @($actionChoice, $applyButton, $quickButton, $fullButton, $signaturesButton)) { $actionsPanel.Controls.Add($control) }
$actionDescription = New-Object System.Windows.Forms.Label
$actionDescription.Dock = 'Fill'
$actionDescription.Padding = New-Object System.Windows.Forms.Padding(5, 3, 5, 0)
$actionDescription.Text = 'اختر إجراءً لقراءة أثره قبل تطبيقه. التحديث والفحص الشامل قد يستغرقان عدة دقائق.'
$actionsLayout.Controls.Add($actionsPanel, 0, 0)
$actionsLayout.Controls.Add($actionDescription, 0, 1)
$layout.Controls.Add($actionsLayout, 0, 3)

$summaryLabel = New-Object System.Windows.Forms.Label
$summaryLabel.Dock = 'Fill'
$summaryLabel.Text = 'لم يكتمل الفحص بعد.'
$summaryLabel.TextAlign = 'MiddleRight'
$layout.Controls.Add($summaryLabel, 0, 4)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.RightToLeftLayout = $true
$findingsTab = New-Object System.Windows.Forms.TabPage
$findingsTab.Text = 'نتائج تحتاج مراجعة'
$evidenceTab = New-Object System.Windows.Forms.TabPage
$evidenceTab.Text = 'الأدلة والفحوص غير المكتملة'
[void]$tabs.TabPages.Add($findingsTab)
[void]$tabs.TabPages.Add($evidenceTab)
$layout.Controls.Add($tabs, 0, 5)

$findingsSplit = New-Object System.Windows.Forms.SplitContainer
$findingsSplit.Size = New-Object System.Drawing.Size(1060, 440)
$findingsSplit.Dock = 'Fill'
$findingsSplit.Orientation = 'Horizontal'
$findingsSplit.SplitterDistance = 230
$findingsSplit.Panel1MinSize = 120
$findingsSplit.Panel2MinSize = 80
$findingsTab.Controls.Add($findingsSplit)
$findingsGrid = New-Object System.Windows.Forms.DataGridView
$findingsGrid.Dock = 'Fill'
$findingsGrid.ReadOnly = $true
$findingsGrid.AllowUserToAddRows = $false
$findingsGrid.AllowUserToDeleteRows = $false
$findingsGrid.MultiSelect = $false
$findingsGrid.SelectionMode = 'FullRowSelect'
$findingsGrid.RowHeadersVisible = $false
$findingsGrid.AutoSizeRowsMode = 'DisplayedCells'
$findingsGrid.DefaultCellStyle.WrapMode = 'True'
$findingsGrid.BackgroundColor = [Drawing.Color]::White
$findingsGrid.AutoGenerateColumns = $false
foreach ($definition in @(@('Severity', 'الأولوية', 95), @('Title', 'النتيجة', 280), @('Detail', 'التفاصيل', 550))) {
    $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column.Name = $definition[0]
    $column.HeaderText = $definition[1]
    $column.Width = $definition[2]
    $column.SortMode = 'NotSortable'
    if ($definition[0] -eq 'Detail') { $column.AutoSizeMode = 'Fill' }
    [void]$findingsGrid.Columns.Add($column)
}
$findingsSplit.Panel1.Controls.Add($findingsGrid)
$findingDetail = New-Object System.Windows.Forms.TextBox
$findingDetail.Multiline = $true
$findingDetail.ReadOnly = $true
$findingDetail.Dock = 'Fill'
$findingDetail.ScrollBars = 'Vertical'
$findingDetail.BackColor = [Drawing.Color]::White
$findingDetail.Text = 'اختر نتيجة لعرض تفاصيلها. لا تُعد المؤشرات دليلًا قاطعًا على وجود مهاجم.'
$findingsSplit.Panel2.Controls.Add($findingDetail)

$evidenceLayout = New-Object System.Windows.Forms.TableLayoutPanel
$evidenceLayout.Dock = 'Fill'
$evidenceLayout.RowCount = 2
$evidenceLayout.ColumnCount = 1
[void]$evidenceLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 38)))
[void]$evidenceLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$sectionChoice = New-Object System.Windows.Forms.ComboBox
$sectionChoice.DropDownStyle = 'DropDownList'
$sectionChoice.Dock = 'Fill'
$evidenceText = New-Object System.Windows.Forms.TextBox
$evidenceText.Dock = 'Fill'
$evidenceText.Multiline = $true
$evidenceText.ReadOnly = $true
$evidenceText.ScrollBars = 'Both'
$evidenceText.WordWrap = $false
$evidenceText.RightToLeft = 'No'
$evidenceText.Font = New-Object System.Drawing.Font('Consolas', 10)
$evidenceText.BackColor = [Drawing.Color]::White
$evidenceLayout.Controls.Add($sectionChoice, 0, 0)
$evidenceLayout.Controls.Add($evidenceText, 0, 1)
$evidenceTab.Controls.Add($evidenceLayout)

$statusPanel = New-Object System.Windows.Forms.TableLayoutPanel
$statusPanel.Dock = 'Fill'
$statusPanel.ColumnCount = 1
$statusPanel.RowCount = 2
[void]$statusPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
[void]$statusPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Dock = 'Fill'
$statusLabel.AutoEllipsis = $true
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock = 'Fill'
$progress.Style = 'Marquee'
$progress.MarqueeAnimationSpeed = 40
$progress.Visible = $false
$statusPanel.Controls.Add($statusLabel, 0, 0)
$statusPanel.Controls.Add($progress, 0, 1)
$layout.Controls.Add($statusPanel, 0, 6)

$scanButton.Add_Click({ Start-GuardWork -Operation Scan -Description 'جارٍ فحص الإعدادات والسجلات المتاحة؛ لا تُغيّر هذه العملية الإعدادات.' })
$reportButton.Add_Click({
    try { Start-Process -FilePath $script:LatestPaths.HtmlPath -ErrorAction Stop } catch { Show-GuardMessage -Message $_.Exception.Message -Failure }
})
$folderButton.Add_Click({
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList (ConvertTo-GuardNativeArgument $OutputDirectory) -ErrorAction Stop } catch { Show-GuardMessage -Message $_.Exception.Message -Failure }
})
$securityButton.Add_Click({
    try { Start-Process -FilePath 'windowsdefender:' -ErrorAction Stop } catch { Show-GuardMessage -Message $_.Exception.Message -Failure }
})
$updateButton.Add_Click({
    try { Start-Process -FilePath 'ms-settings:windowsupdate' -ErrorAction Stop } catch { Show-GuardMessage -Message $_.Exception.Message -Failure }
})
$adminButton.Add_Click({
    if (-not (Confirm-GuardOperation 'سيطلب Windows موافقتك عبر UAC لفتح نسخة بصلاحيات المسؤول. لا يُطبّق هذا أي إصلاح تلقائي. هل تريد المتابعة؟')) { return }
    try {
        $arguments = '-NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File ' + (ConvertTo-GuardNativeArgument $script:EntryPointPath) + ' -OutputDirectory ' + (ConvertTo-GuardNativeArgument $OutputDirectory)
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -ArgumentList $arguments -ErrorAction Stop
        $form.Close()
    } catch { Show-GuardMessage -Message ('لم تُفتح نسخة المسؤول: ' + $_.Exception.Message) -Failure }
})
$actionChoice.Add_SelectedIndexChanged({
    if ($actionChoice.SelectedIndex -ge 0) {
        $actionDescription.Text = [string]$actionChoice.SelectedItem.Description
        $applyButton.Enabled = -not $script:Busy -and $script:Privileged
    }
})
$applyButton.Add_Click({
    if ($actionChoice.SelectedIndex -lt 0 -or -not $script:Privileged) { return }
    $action = $actionChoice.SelectedItem
    $message = [string]$action.Title + [Environment]::NewLine + [Environment]::NewLine + [string]$action.Description + [Environment]::NewLine + [Environment]::NewLine + 'سيُحفظ سجل تغيير محلي ثم يُعاد فحص الحالة. هل توافق على تطبيق هذا الإجراء؟'
    if (Confirm-GuardOperation $message) { Start-GuardWork -Operation Action -Argument $action.Id -Description ('جارٍ تطبيق: ' + $action.Title) }
})
$quickButton.Add_Click({
    if (Confirm-GuardOperation 'تشغيل فحص سريع باستخدام Microsoft Defender. قد لا يتاح إذا كانت الحماية مُدارة ببرنامج آخر. هل تريد بدء الفحص؟') { Start-GuardWork -Operation DefenderScan -Argument QuickScan -Description 'Microsoft Defender يجري فحصًا سريعًا. انتظر انتهاء العملية.' }
})
$fullButton.Add_Click({
    if (Confirm-GuardOperation 'تشغيل فحص كامل باستخدام Microsoft Defender. قد يستغرق وقتًا طويلًا ويزيد استخدام المعالج والقرص. هل تريد بدء الفحص؟') { Start-GuardWork -Operation DefenderScan -Argument FullScan -Description 'Microsoft Defender يجري فحصًا كاملًا؛ قد يستغرق وقتًا طويلًا.' }
})
$signaturesButton.Add_Click({
    if (Confirm-GuardOperation 'تحديث تعريفات Microsoft Defender يستخدم الاتصال بالشبكة للوصول إلى خدمات تحديث Microsoft أو مصدر التحديث الذي حدّدته إدارة جهازك. هل توافق على بدء التحديث؟') { Start-GuardWork -Operation UpdateSignatures -Description 'جارٍ تحديث تعريفات Microsoft Defender عبر مصدر تحديث Windows.' }
})
$findingsGrid.Add_SelectionChanged({
    if ($findingsGrid.SelectedRows.Count -gt 0) {
        $finding = $findingsGrid.SelectedRows[0].Tag
        if ($null -ne $finding) { $findingDetail.Text = [string]$finding.Title + [Environment]::NewLine + [Environment]::NewLine + [string]$finding.Detail }
    }
})
$sectionChoice.Add_SelectedIndexChanged({ Show-GuardSection })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    if ($null -eq $script:PendingTask -or -not $script:PendingTask.Handle.IsCompleted) { return }
    $task = $script:PendingTask
    $script:PendingTask = $null
    $result = @()
    $failure = $null
    try {
        $result = @($task.PowerShell.EndInvoke($task.Handle))
        if ($task.PowerShell.Streams.Error.Count -gt 0) { throw ($task.PowerShell.Streams.Error | Out-String) }
    } catch { $failure = $_.Exception.Message } finally {
        $task.PowerShell.Dispose()
        $task.Runspace.Dispose()
    }
    if ($null -ne $failure) {
        Set-GuardBusy -Value $false -Message 'تعذر إكمال العملية. راجع الرسالة؛ لم يُسجّل نجاح.'
        Show-GuardMessage -Message $failure -Failure
        if ($task.Operation -eq 'Action') { Start-GuardWork -Operation Scan -Description 'جارٍ مراجعة الحالة بعد تعذر الإجراء؛ قد يكون التغيير جزئيًا.' }
        return
    }
    if ($task.Operation -eq 'Scan') {
        if ($result.Count -ne 1) {
            Set-GuardBusy -Value $false -Message 'لم يعد الفحص تقريرًا صالحًا.'
            Show-GuardMessage -Message 'لم يعد الفحص تقريرًا واحدًا صالحًا. لم تُحدّث النتائج المعروضة.' -Failure
            return
        }
        try { Show-GuardReport -Report $result[0] } catch {
            Set-GuardBusy -Value $false -Message 'تعذر عرض تقرير الفحص.'
            Show-GuardMessage -Message $_.Exception.Message -Failure
        }
    } else {
        $message = 'انتهت العملية. راجع أمان Windows لحالة Defender وتاريخ الحماية.'
        $success = $true
        if ($result.Count -gt 0) {
            $last = $result[$result.Count - 1]
            if ($last -is [string]) { $message = $last }
            if ($null -ne $last.PSObject.Properties['Success']) { $success = [bool]$last.Success }
            if ($null -ne $last.PSObject.Properties['Message']) { $message = [string]$last.Message }
            if ($null -ne $last.PSObject.Properties['ReceiptPath'] -and -not [string]::IsNullOrWhiteSpace([string]$last.ReceiptPath)) { $message += [Environment]::NewLine + 'سجل التغيير: ' + $last.ReceiptPath }
        }
        Set-GuardBusy -Value $false -Message $message
        Show-GuardMessage -Message $message -Failure:(-not $success)
        if ($success -or $task.Operation -eq 'Action') { Start-GuardWork -Operation Scan -Description 'جارٍ إعادة فحص الحالة بعد العملية، بما فيها أي تغيير جزئي.' }
    }
})
$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($script:Busy) {
        $eventArgs.Cancel = $true
        Show-GuardMessage -Message 'هناك عملية قيد التنفيذ. انتظر انتهاءها قبل إغلاق البرنامج؛ يمكنك متابعة حالة الفحص من أمان Windows.'
    }
})
$form.Add_Shown({ Start-GuardWork -Operation Scan -Description 'جارٍ فحص الإعدادات والسجلات المتاحة؛ لا تُغيّر هذه العملية الإعدادات.' })
Set-GuardBusy -Value $false -Message 'جاهز للفحص المحلي.'
$timer.Start()
try { [void]$form.ShowDialog() } finally {
    $timer.Stop()
    $timer.Dispose()
    if ($null -ne $script:PendingTask) {
        $script:PendingTask.PowerShell.Stop()
        $script:PendingTask.PowerShell.Dispose()
        $script:PendingTask.Runspace.Dispose()
    }
    $form.Dispose()
}
