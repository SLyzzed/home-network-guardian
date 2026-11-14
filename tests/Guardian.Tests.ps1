. (Join-Path $PSScriptRoot '..\Guardian.ps1')
$script:Fixture = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\samples\service_example.xml'))
$script:Prompt = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\AI_Prompt.txt'))

function New-TestNetwork {
    [pscustomobject]@{ Index = 4; Name = 'Home Wi-Fi'; Address = '192.168.1.42'; Prefix = 24; Scope = '192.168.1.0/24'; Hardware = $true; Description = 'Wireless' }
}
function New-TestXml([string]$Address = '192.168.1.10') {
    return '<nmaprun><host><status state="up"/><address addr="' + $Address + '" addrtype="ipv4"/><address addr="02:00:00:00:00:77" addrtype="mac" vendor="Espressif Fictional-private"/><hostnames><hostname name="Fictional-private"/></hostnames><ports><port protocol="tcp" portid="554"><state state="open"/><service name="rtsp" method="probed" product="Fictional-private"/><script id="rtsp-methods" output="PLAY Fictional-private"/></port></ports></host></nmaprun>'
}

Describe 'Private network scope' {
    It 'limits a larger subnet to the containing /24' { Get-PrivateScope '10.20.30.42' 8 | Should Be '10.20.30.0/24' }
    It 'retains smaller subnets' { Get-PrivateScope '192.168.1.130' 25 | Should Be '192.168.1.128/25' }
    It 'supports a private /32' { Get-PrivateScope '192.168.1.42' 32 | Should Be '192.168.1.42/32' }
    foreach ($address in @('203.0.113.8','127.0.0.1','169.254.1.1','100.64.1.1','::1','bad','192.168.1.0','192.168.1.255')) {
        It "rejects $address" { { Get-PrivateScope $address 24 } | Should Throw }
    }
    It 'rejects a subnet that expands outside private space' { { Get-PrivateScope '192.168.1.42' 8 } | Should Throw }
    It 'rejects out-of-scope targets and hostnames' {
        foreach ($target in @('192.168.2.1','203.0.113.8','example.com','::1','192.168.1.255')) {
            Test-Target $target (New-TestNetwork) | Should Be $false
        }
    }
}

Describe 'Network selection and prerequisites' {
    It 'selects a single physical private network' {
        Mock Get-NetworkRows { New-TestNetwork }
        (Select-Network).Address | Should Be '192.168.1.42'
    }
    It 'stops on multiple candidate networks' {
        Mock Get-NetworkRows { New-TestNetwork; New-TestNetwork }
        { Select-Network } | Should Throw
    }
    It 'stops on a VPN or virtual adapter' {
        Mock Get-NetworkRows { $n = New-TestNetwork; $n.Name = 'VPN'; $n }
        { Select-Network } | Should Throw
    }
    It 'stops when no network is eligible' {
        Mock Get-NetworkRows { }
        { Select-Network } | Should Throw
    }
    It 'explains missing Nmap without installing it' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'nmap.exe' }
        Mock Test-Path { $false }
        { Find-Nmap } | Should Throw 'Nmap is missing'
    }
    It 'locates Nmap under a path containing spaces' {
        Mock Get-Command { [pscustomobject]@{ Source = 'C:\Program Files\Nmap\nmap.exe' } } -ParameterFilter { $Name -eq 'nmap.exe' }
        Find-Nmap | Should Be 'C:\Program Files\Nmap\nmap.exe'
    }
    It 'explains missing Npcap' {
        Mock Get-Service { $null }
        { Assert-Npcap } | Should Throw 'Npcap is missing'
    }
    It 'accepts an installed Npcap service' {
        Mock Get-Service { [pscustomobject]@{ Name = 'npcap' } }
        Assert-Npcap
    }
}

Describe 'Exact bounded Nmap commands' {
    It 'uses discovery only for the private subnet' {
        $a = New-NmapArguments (New-TestNetwork)
        $a[0] | Should Be '-sn'
        $a[-1] | Should Be '192.168.1.0/24'
        ($a -contains '-n') | Should Be $true
    }
    It 'uses only allowed ports and explicitly selected safe scripts' {
        $a = New-NmapArguments (New-TestNetwork) '192.168.1.10'
        $a[$a.IndexOf('-p') + 1] | Should Be '80,81,443,554,8000,8080,8554,8899'
        $a[$a.IndexOf('--script') + 1] | Should Be 'ssl-cert,rtsp-methods'
        $a[$a.IndexOf('--version-intensity') + 1] | Should Be '0'
        $a[$a.IndexOf('--host-timeout') + 1] | Should Be '45s'
        $a[$a.IndexOf('--script-timeout') + 1] | Should Be '10s'
        $a[-1] | Should Be '192.168.1.10'
        ($a -contains '-sC') | Should Be $false
        ($a -contains '-A') | Should Be $false
    }
    It 'rejects untrusted command arguments before starting a process' {
        { Invoke-Nmap 'not-a-program' @('hello; calc') 100 } | Should Throw 'Invalid scanner argument'
    }
    It 'rejects expired deadlines before starting a process' {
        { Invoke-Nmap 'not-a-program' @('-sn') 0 } | Should Throw 'deadline'
    }
    It 'rejects scope expansion at command construction' {
        { New-NmapArguments (New-TestNetwork) '192.168.2.1' } | Should Throw
    }
}

Describe 'XML and private export' {
    It 'parses synthetic service evidence and skips closed ports' {
        $data = @(Read-ScanXml (New-TestXml))
        $data.Count | Should Be 1
        $data[0].Ports[0].Service | Should Be 'rtsp'
        $data[0].Ports[0].Rtsp | Should Be $true
        @(Read-ScanXml '<nmaprun><host><status state="down"/></host></nmaprun>').Count | Should Be 0
        $d = @(Read-ScanXml '<nmaprun><host><status state="up"/><ports><port portid="80"><state state="closed"/></port></ports></host></nmaprun>')
        @($d[0].Ports).Count | Should Be 0
    }
    foreach ($xml in @('', '<bad>', '<other/>', '<nmaprun><host><status state="up"/><ports><port portid="bad"><state state="open"/></port></ports></host></nmaprun>', '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>')) {
        It 'rejects malformed or unsuccessful XML' { { Read-ScanXml $xml } | Should Throw }
    }
    It 'does not resolve external XML entities' {
        { Read-ScanXml '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///C:/private">]><nmaprun>&x;</nmaprun>' } | Should Throw
    }
    It 'redacts identifiers in every raw evidence field' {
        $data = @(Read-ScanXml (New-TestXml))
        $text = New-AiReview ([pscustomobject]@{ Devices = $data; Notes = @() }) $script:Prompt
        foreach ($secret in @('192.168.1.10','02:00:00:00:00:77','Fictional-private')) { $text.Contains($secret) | Should Be $false }
        $text | Should Match 'Device 1'
        $text | Should Match 'Espressif'
        $text | Should Match 'Open TCP port 554: rtsp'
        $text | Should Match 'Response-based identification'
    }
    It 'distinguishes port guesses from response-based identification' {
        $data = @(Read-ScanXml ((New-TestXml).Replace('method="probed"', 'method="table"')))
        (New-AiReview ([pscustomobject]@{ Devices = $data; Notes = @() }) $script:Prompt) | Should Match 'Port-based guess only'
    }
    It 'handles missing information and no devices' {
        $text = New-AiReview ([pscustomobject]@{ Devices = @(); Notes = @('Incomplete: discovery timed out') }) $script:Prompt
        $text | Should Match 'Total discovered devices: 0'
        $text | Should Match 'Incomplete: discovery timed out'
        $text | Should Match 'does not mean malicious'
    }
    It 'includes clear AI instructions and a manual-sharing warning' {
        $text = New-AiReview ([pscustomobject]@{ Devices = @(); Notes = @() }) $script:Prompt
        $text.StartsWith('Please explain') | Should Be $true
        foreach ($word in @('plain English','alternative explanations','public web research','Cite sources','external AI service','review','RTSP')) { $text | Should Match $word }
    }
    It 'does not export unrecognised manufacturer or service text' {
        $xml = (New-TestXml).Replace('Espressif Fictional-private','secret-serial-777').Replace('name="rtsp"','name="secret-device"')
        $text = New-AiReview ([pscustomobject]@{ Devices = @(Read-ScanXml $xml); Notes = @() }) $script:Prompt
        $text | Should Not Match 'secret-serial|secret-device'
    }
}

Describe 'Scanning failures and partial results with mocked Nmap' {
    BeforeEach {
        Mock Invoke-Nmap { throw 'Unexpected scanning command' }
        Mock Invoke-Nmap { throw 'Discovery error' } -ParameterFilter { $Arguments -contains '-sn' }
        Mock Invoke-Nmap { throw 'Service timeout' } -ParameterFilter { $Arguments -contains '-sV' }
    }
    It 'checks only addresses discovered as responding' {
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sn' }
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sV' }
        $result = Get-ScanResults 'mock nmap path' (New-TestNetwork)
        $result.Devices.Count | Should Be 1
        $result.Devices[0].Check | Should Match 'completed'
        Assert-MockCalled -Scope It Invoke-Nmap -Times 1 -Exactly -ParameterFilter { $Arguments -contains '-sV' -and $Arguments[-1] -eq '192.168.1.10' -and $TimeoutMs -le 60000 }
    }
    It 'keeps discovery when service checks time out' {
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sn' }
        $result = Get-ScanResults 'mock' (New-TestNetwork)
        $result.Devices.Count | Should Be 1
        $result.Devices[0].Check | Should Match 'Incomplete'
    }
    It 'marks discovery errors instead of claiming no devices exist' {
        $result = Get-ScanResults 'mock' (New-TestNetwork)
        $result.Notes.Count | Should Be 1
        $result.Notes[0] | Should Match 'failed'
    }
    It 'never inspects out-of-scope discoveries' {
        Mock Invoke-Nmap { New-TestXml '203.0.113.8' } -ParameterFilter { $Arguments -contains '-sn' }
        $result = Get-ScanResults 'mock' (New-TestNetwork)
        Assert-MockCalled -Scope It Invoke-Nmap -Times 0 -Exactly -ParameterFilter { $Arguments -contains '-sV' }
        $result.Notes.Count | Should Be 1
    }
    It 'does not treat malformed service XML as a completed check' {
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sn' }
        Mock Invoke-Nmap { '<bad>' } -ParameterFilter { $Arguments -contains '-sV' }
        (Get-ScanResults 'mock' (New-TestNetwork)).Devices[0].Check | Should Match 'Incomplete'
    }
}

Describe 'Consent, output and Notepad orchestration' {
    BeforeEach {
        Mock Find-Nmap { 'C:\Program Files\Nmap\nmap.exe' }
        Mock Assert-Npcap { }
        Mock Select-Network { New-TestNetwork }
        Mock Confirm-Scan { $true }
        Mock Get-ScanResults { [pscustomobject]@{ Devices = @(); Notes = @() } }
        Mock Save-Review { 'C:\Local App Data\HomeNetworkGuardian\AI_Review.txt' }
        Mock Open-Review { }
        Mock Show-Results { }
        Mock Show-Notice { }
    }
    It 'cancellation prevents scanning and output' {
        Mock Confirm-Scan { $false }
        Start-Guardian
        Assert-MockCalled -Scope It Get-ScanResults -Times 0 -Exactly
        Assert-MockCalled -Scope It Save-Review -Times 0 -Exactly
        Assert-MockCalled -Scope It Open-Review -Times 0 -Exactly
        Assert-MockCalled -Scope It Show-Results -Times 0 -Exactly
    }
    It 'revalidates the network and displays the successful output' {
        Start-Guardian
        Assert-MockCalled -Scope It Select-Network -Times 2 -Exactly
        Assert-MockCalled -Scope It Get-ScanResults -Times 1 -Exactly
        Assert-MockCalled -Scope It Show-Results -Times 1 -Exactly -ParameterFilter { $Path -eq 'C:\Local App Data\HomeNetworkGuardian\AI_Review.txt' -and $DeviceCount -eq 0 }
        Assert-MockCalled -Scope It Open-Review -Times 0 -Exactly
    }
    It 'stops if the interface changes after consent' {
        $script:NetworkCalls = 0
        Mock Select-Network { $script:NetworkCalls++; $n = New-TestNetwork; if ($script:NetworkCalls -gt 1) { $n.Address = '192.168.1.50' }; $n }
        Start-Guardian
        Assert-MockCalled -Scope It Get-ScanResults -Times 0 -Exactly
        Assert-MockCalled -Scope It Show-Notice -Times 1 -Exactly -ParameterFilter { $Text -match 'changed' }
    }
    It 'gives a saved path if Notepad fails' {
        Mock Show-Results { throw 'No display' }
        Mock Open-Review { throw 'blocked' }
        Start-Guardian
        Assert-MockCalled -Scope It Show-Notice -Times 1 -Exactly -ParameterFilter { $Text -match 'saved' }
    }
    It 'falls back to Notepad if the popup fails' {
        Mock Show-Results { throw 'No display' }
        Start-Guardian
        Assert-MockCalled -Scope It Open-Review -Times 1 -Exactly
    }
    It 'does not display results when saving fails' {
        Mock Save-Review { throw 'Cannot save report' }
        Start-Guardian
        Assert-MockCalled -Scope It Show-Results -Times 0 -Exactly
        Assert-MockCalled -Scope It Open-Review -Times 0 -Exactly
        Assert-MockCalled -Scope It Show-Notice -Times 1 -Exactly
    }
    It 'displays partial results with their discovered count and timeout evidence' {
        Mock Get-ScanResults { [pscustomobject]@{ Devices = @(Read-ScanXml (New-TestXml)); Notes = @('Five-minute scanning deadline reached.') } }
        Start-Guardian
        Assert-MockCalled -Scope It Save-Review -Times 1 -Exactly -ParameterFilter { $Text -match 'deadline reached' -and $Text -match 'Device 1' }
        Assert-MockCalled -Scope It Show-Results -Times 1 -Exactly -ParameterFilter { $DeviceCount -eq 1 }
    }
    It 'does not scan or show results when prerequisites fail' {
        Mock Find-Nmap { throw 'Nmap is missing' }
        Start-Guardian
        Assert-MockCalled -Scope It Get-ScanResults -Times 0 -Exactly
        Assert-MockCalled -Scope It Show-Results -Times 0 -Exactly
    }
}

Describe 'Results popup and explicit clipboard actions' {
    It 'uses retained callbacks after Guardian functions leave scope and copies the actual complete clipboard text' {
        $log = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -STA -File (Join-Path $PSScriptRoot 'Popup.Regression.ps1') -WorkDirectory $TestDrive 2>&1
        $LASTEXITCODE | Should Be 0
        $log -join "`n" | Should Match 'Popup regression passed'
    }
    It 'contains clipboard and Notepad callback errors after Guardian functions leave scope' {
        $log = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -STA -File (Join-Path $PSScriptRoot 'Popup.Regression.ps1') -WorkDirectory $TestDrive -FailActions 2>&1
        $LASTEXITCODE | Should Be 0
        $log -join "`n" | Should Match 'Popup regression passed'
    }
    It 'rejects non-STA clipboard access and popup creation before touching the clipboard' {
        $guardian = Join-Path $PSScriptRoot '..\Guardian.ps1'
        $code = '. ' + "'" + $guardian.Replace("'", "''") + "'" + '; try { Set-ReviewClipboard test; exit 2 } catch { if ($_.Exception.Message -notmatch "STA") { exit 3 } }; try { New-ResultsWindow test 0; exit 4 } catch { if ($_.Exception.Message -notmatch "STA") { exit 5 } }; exit 0'
        & (Join-Path $PSHOME 'powershell.exe') -NoProfile -MTA -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))
        $LASTEXITCODE | Should Be 0
    }
    It 'copies the complete saved report including Unicode, prompt and timeout notes' {
        $path = Join-Path $TestDrive 'AI_Review.txt'
        $text = New-AiReview ([pscustomobject]@{ Devices = @(); Notes = @('Incomplete: discovery timed out') }) $script:Prompt
        $text += "Unicode: $([char]0x03A9)`r`n" + ('Long evidence line' * 10000)
        [IO.File]::WriteAllText($path, $text)
        Mock Set-ReviewClipboard { }
        Copy-Review $path | Should Match 'Copied successfully'
        Assert-MockCalled -Scope It Set-ReviewClipboard -Times 1 -Exactly -ParameterFilter { $Text -ceq $text }
    }
    It 'explains clipboard and file errors without claiming success' {
        $path = Join-Path $TestDrive 'AI_Review.txt'
        [IO.File]::WriteAllText($path, 'Synthetic only')
        Mock Set-ReviewClipboard { throw 'Clipboard busy' }
        Copy-Review $path | Should Match 'Could not copy.*Try again'
        Copy-Review (Join-Path $TestDrive 'missing.txt') | Should Match 'Could not copy'
        Assert-MockCalled -Scope It Set-ReviewClipboard -Times 1 -Exactly
    }
    It 'shows a real modal popup, copies only on click, opens on click and closes' {
        $path = Join-Path $TestDrive 'popup.txt'
        [IO.File]::WriteAllText($path, 'Synthetic popup evidence')
        Mock Set-ReviewClipboard { }
        Mock Open-Review { }
        $form = New-ResultsWindow $path 7
        try {
            $form.Controls[0].Controls[1].Text | Should Match 'Devices discovered: 7'
            ($form.Controls[0].Controls | ForEach-Object Text) -join ' ' | Should Match 'clipboard history or syncing'
            Assert-MockCalled -Scope It Set-ReviewClipboard -Times 0 -Exactly
            $timer = New-Object System.Windows.Forms.Timer
            $timer.Interval = 250
            $script:PopupError = $null
            $timer.Add_Tick({
                $timer.Stop()
                try {
                    $form.Controls.Find('CopyForAI', $true)[0].PerformClick()
                    $form.Controls.Find('OpenReport', $true)[0].PerformClick()
                    $form.Controls.Find('CloseResults', $true)[0].PerformClick()
                } catch { $script:PopupError = $_ }
                finally { $form.Close() }
            })
            try { $timer.Start(); [void]$form.ShowDialog() } finally { $timer.Dispose() }
            if ($script:PopupError) { throw $script:PopupError }
            $form.Controls.Find('CopyStatus', $true)[0].Text | Should Match 'Copied successfully'
            Assert-MockCalled -Scope It Set-ReviewClipboard -Times 1 -Exactly -ParameterFilter { $Text -eq 'Synthetic popup evidence' }
            Assert-MockCalled -Scope It Open-Review -Times 1 -Exactly -ParameterFilter { $Path -eq $path }
        } finally { $form.Dispose() }
    }
}

Describe 'Actual local file writing and mocked Windows launch' {
    It 'writes UTF-8 text under Local AppData including spaces' {
        $old = $env:LOCALAPPDATA
        try {
            $env:LOCALAPPDATA = Join-Path $TestDrive 'Local App Data'
            $path = Save-Review 'Synthetic example only'
            [IO.File]::ReadAllText($path) | Should Be 'Synthetic example only'
            $path | Should Match 'HomeNetworkGuardian\\AI_Review.txt$'
        } finally { $env:LOCALAPPDATA = $old }
    }
    It 'quotes the Notepad document path' {
        Mock Start-Process { }
        Open-Review 'C:\Local App Data\AI_Review.txt'
        Assert-MockCalled -Scope It Start-Process -Times 1 -Exactly -ParameterFilter { $ArgumentList -eq '"C:\Local App Data\AI_Review.txt"' -and $FilePath -like '*notepad.exe' }
    }
    It 'launcher quotes its script path without policy bypass or elevation' {
        $batch = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Start Guardian.bat'))
        $batch.Contains('"%~dp0Guardian.ps1"') | Should Be $true
        $batch | Should Not Match 'ExecutionPolicy|Bypass|RunAs'
    }
}

Describe 'Overall deadline and preservation of completed devices' {
    It 'stops scheduling devices at five minutes while keeping the first result' {
        $script:ClockCalls = 0
        Mock Get-ScanElapsed { $script:ClockCalls++; if ($script:ClockCalls -eq 1) { 10 } else { 300001 } }
        Mock Invoke-Nmap {
            '<nmaprun>' + (New-TestXml).Replace('<nmaprun>','').Replace('</nmaprun>','') +
                (New-TestXml '192.168.1.11').Replace('<nmaprun>','').Replace('</nmaprun>','') + '</nmaprun>'
        } -ParameterFilter { $Arguments -contains '-sn' }
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sV' }
        $result = Get-ScanResults 'mock' (New-TestNetwork)
        $result.Devices[0].Check | Should Match 'completed'
        $result.Devices[1].Check | Should Match 'five-minute'
        $result.Notes -join ' ' | Should Match 'deadline'
        Assert-MockCalled -Scope It Invoke-Nmap -Times 1 -Exactly -ParameterFilter { $Arguments -contains '-sV' }
    }
    It 'bounds service timeout to the remaining overall budget' {
        Mock Get-ScanElapsed { 299900 }
        Mock Invoke-Nmap { New-TestXml }
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sn' }
        Mock Invoke-Nmap { New-TestXml } -ParameterFilter { $Arguments -contains '-sV' }
        [void](Get-ScanResults 'mock' (New-TestNetwork))
        Assert-MockCalled -Scope It Invoke-Nmap -Times 1 -Exactly -ParameterFilter { $Arguments -contains '-sV' -and $TimeoutMs -eq 100 }
    }
}

function New-FakeProcess([bool]$Timeout = $false, [int]$Code = 0) {
    $fake = [pscustomobject]@{ HasExited = $false; ExitCode = $Code; TimedOut = $Timeout; Killed = $false; Disposed = $false
        StandardOutput = (New-Object IO.StringReader('<nmaprun/>')); StandardError = (New-Object IO.StringReader('private diagnostic')) }
    $fake | Add-Member ScriptMethod Start { return $true }
    $fake | Add-Member ScriptMethod WaitForExit { param($Milliseconds); if ($this.TimedOut -and -not $this.Killed) { return $false }; $this.HasExited = $true; return $true }
    $fake | Add-Member ScriptMethod Kill { $this.Killed = $true; $this.HasExited = $true }
    $fake | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
    return $fake
}

Describe 'Mocked scanner process lifecycle' {
    It 'kills and disposes a timed-out scan process' {
        $script:Fake = New-FakeProcess $true
        Mock New-ScanProcess { $script:Fake }
        { Invoke-Nmap 'C:\Program Files\Nmap\nmap.exe' @('-sn','192.168.1.0/24') 10 } | Should Throw 'timed out'
        $script:Fake.Killed | Should Be $true
        $script:Fake.Disposed | Should Be $true
    }
    It 'handles nonzero scanner exit without leaking diagnostics' {
        $script:Fake = New-FakeProcess $false 1
        Mock New-ScanProcess { $script:Fake }
        { Invoke-Nmap 'mock' @('-sn') 10 } | Should Throw 'Nmap failed'
        $script:Fake.Disposed | Should Be $true
    }
    It 'keeps executable paths separate from arguments and avoids a shell' {
        $script:Fake = New-FakeProcess
        Mock New-ScanProcess {
            $script:CapturedInfo = $Info
            $script:Fake
        }
        Invoke-Nmap 'C:\Program Files\Nmap\nmap.exe' @('-sn','192.168.1.0/24') 10 | Should Be '<nmaprun/>'
        $script:CapturedInfo.FileName | Should Be 'C:\Program Files\Nmap\nmap.exe'
        $script:CapturedInfo.UseShellExecute | Should Be $false
        $script:CapturedInfo.Arguments | Should Be '-sn 192.168.1.0/24'
    }
    It 'disposes a process when starting Nmap fails' {
        $script:Fake = New-FakeProcess
        $script:Fake | Add-Member ScriptMethod Start { throw 'Start failed' } -Force
        Mock New-ScanProcess { $script:Fake }
        { Invoke-Nmap 'mock' @('-sn') 10 } | Should Throw 'Start failed'
        $script:Fake.Disposed | Should Be $true
    }
    It 'flags a process Windows will not terminate' {
        $script:ScanTerminationFailed = $false
        $script:Fake = New-FakeProcess $true
        $script:Fake | Add-Member ScriptMethod Kill { throw 'Access denied' } -Force
        Mock New-ScanProcess { $script:Fake }
        { Invoke-Nmap 'mock' @('-sn') 10 } | Should Throw
        $script:ScanTerminationFailed | Should Be $true
        $script:Fake.Disposed | Should Be $true
    }
}
