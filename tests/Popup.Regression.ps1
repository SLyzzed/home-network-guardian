# Standalone process: no Pester mocks or globally dot-sourced Guardian functions.
param([Parameter(Mandatory = $true)][string]$WorkDirectory, [switch]$FailActions)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-ScopedPopup([string]$ReportPath) {
    . (Join-Path $PSScriptRoot '..\Guardian.ps1')
    if ($FailActions) {
        function Set-ReviewClipboard([string]$Text) { throw 'Simulated busy clipboard' }
        function Open-Review([string]$Path) { throw 'Simulated blocked Notepad' }
    } else {
        # Notepad's exact executable and quoting are checked in Guardian.Tests.ps1.
        function Open-Review([string]$Path) { [IO.File]::WriteAllText(($Path + '.opened'), $Path) }
    }
    New-ResultsWindow $ReportPath 3
}

Add-Type -AssemblyName System.Windows.Forms
$previousClipboard = [System.Windows.Forms.Clipboard]::GetDataObject()
$form = $null
$timer = $null
try {
    $path = Join-Path $WorkDirectory 'report with spaces.txt'
    $prompt = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\AI_Prompt.txt'))
    $expected = $prompt + "`r`nTotal discovered devices: 3`r`nIncomplete: five-minute deadline reached`r`n" +
        ("Synthetic evidence $([char]0x03A9)`r`n" * 10000) + "END OF COMPLETE REPORT`r`n"
    [IO.File]::WriteAllText($path, $expected, (New-Object Text.UTF8Encoding($true)))
    [System.Windows.Forms.Clipboard]::SetText('Synthetic clipboard sentinel')
    $form = New-ScopedPopup $path
    if (Get-Command Copy-Review -ErrorAction SilentlyContinue) { throw 'Regression requires Copy-Review to be out of scope.' }
    if ([System.Windows.Forms.Clipboard]::GetText() -cne 'Synthetic clipboard sentinel') { throw 'Popup copied before a click.' }
    $script:CallbackError = $null
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100
    $timer.Add_Tick({
        $timer.Stop()
        try {
            $form.Controls.Find('CopyForAI', $true)[0].PerformClick()
            $status = $form.Controls.Find('CopyStatus', $true)[0].Text
            if ($FailActions) {
                if ($status -notmatch '^Could not copy') { throw 'Clipboard failure was not explained.' }
                if ([System.Windows.Forms.Clipboard]::GetText() -cne 'Synthetic clipboard sentinel') { throw 'Failed copy changed the clipboard.' }
            } else {
                if ($status -notmatch '^Copied successfully') { throw "Copy callback failed: $status" }
                if ([System.Windows.Forms.Clipboard]::GetText() -cne $expected) { throw 'Clipboard does not contain the entire report.' }
            }
            $form.Controls.Find('OpenReport', $true)[0].PerformClick()
            if ($FailActions) {
                if ($form.Controls.Find('CopyStatus', $true)[0].Text -notmatch 'Notepad could not open') { throw 'Notepad failure was not explained.' }
            } elseif ([IO.File]::ReadAllText(($path + '.opened')) -cne $path) { throw 'Open Report used the wrong path.' }
            $form.Controls.Find('CloseResults', $true)[0].PerformClick()
            if ($form.DialogResult -ne 'Cancel') { throw 'Close did not request dismissal.' }
        } catch { $script:CallbackError = $_ }
        finally { if ($script:CallbackError) { $form.Close() } }
    })
    $timer.Start()
    [void]$form.ShowDialog()
    if ($script:CallbackError) { throw $script:CallbackError }
    if ($form.Visible) { throw 'Close did not dismiss the popup.' }
    'Popup regression passed'
} finally {
    if ($timer) { $timer.Dispose() }
    if ($form) { $form.Dispose() }
    # Tests copy synthetic text only and restore the previous clipboard data.
    if ($previousClipboard) { [System.Windows.Forms.Clipboard]::SetDataObject($previousClipboard, $true) }
    else { [System.Windows.Forms.Clipboard]::Clear() }
}
