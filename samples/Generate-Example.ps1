# Offline synthetic example only. Does not invoke the launcher or any scans.
. (Join-Path $PSScriptRoot '..\Guardian.ps1')
$devices = @(Read-ScanXml ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'service_example.xml'))))
foreach ($device in $devices) { $device.Check = 'SYNTHETIC example: no real scan was performed' }
$results = [pscustomobject]@{ Devices = $devices; Notes = @('SYNTHETIC example using documentation-only addresses; no network scans performed.') }
$prompt = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\AI_Prompt.txt'))
$output = Join-Path $PSScriptRoot 'AI_Review.example.txt'
[IO.File]::WriteAllText($output, (New-AiReview $results $prompt), (New-Object Text.UTF8Encoding($true)))
Write-Output $output
