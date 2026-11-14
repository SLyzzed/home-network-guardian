$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 3.4 -MaximumVersion 4.99 -ErrorAction Stop
$result = Invoke-Pester -Script $PSScriptRoot -PassThru
if ($result.FailedCount -gt 0 -or $result.TotalCount -eq 0) { exit 1 }
