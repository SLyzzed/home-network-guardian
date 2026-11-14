# Display an existing local report only. No scanning, saving or automatic copying.
param([string]$Path = (Join-Path $env:LOCALAPPDATA 'HomeNetworkGuardian\AI_Review.txt'))

. (Join-Path $PSScriptRoot '..\Guardian.ps1')
try {
    $Path = [IO.Path]::GetFullPath($Path)
    if ($Path.StartsWith('\\')) { throw 'Choose a report on a local drive.' }
    $text = [IO.File]::ReadAllText($Path)
    $count = 0
    $match = [regex]::Match($text, '(?m)^Total discovered devices: (\d+)\r?$')
    if (-not $match.Success -or -not [int]::TryParse($match.Groups[1].Value, [ref]$count)) {
        throw 'The selected report does not contain a valid discovered-device count.'
    }
    try { Show-Results $Path $count }
    catch { Open-Review $Path }
} catch { Show-Notice 'Could not display the saved report. Choose a readable local Guardian report with a valid discovered-device count.' }
