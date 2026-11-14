# Explicit allowlist: never archive the repository directory or private reports.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $root 'dist'
[void][IO.Directory]::CreateDirectory($destination)
$files = @('Start Guardian.bat', 'Guardian.ps1', 'AI_Prompt.txt', 'README.md', 'LICENSE')
$paths = @($files | ForEach-Object { Join-Path $root $_ })
foreach ($path in $paths) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Release inputs must be regular files.' }
}
$archive = Join-Path $destination 'HomeNetworkGuardian.zip'
Compress-Archive -LiteralPath $paths -DestinationPath $archive -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    $entries = @($zip.Entries | ForEach-Object FullName)
    if (@(Compare-Object ($files | Sort-Object) ($entries | Sort-Object)).Count) { throw 'Unexpected release archive contents.' }
} finally { $zip.Dispose() }
Write-Output 'Release ZIP verified: three application files, README.md and LICENSE only.'
