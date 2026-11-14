. (Join-Path $PSScriptRoot '..\Guardian.ps1')

Describe 'Privacy regression' {
    It 'rejects report-file reparse points without writing through them' {
        $path = Join-Path $TestDrive 'linked-report.txt'
        Mock Test-Path { $true }
        Mock Get-Item { [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint } }
        { Assert-LocalReportPath $path } | Should Throw 'linked or redirected'
    }
    It 'bounds XML documents and masks parser errors' {
        $xml = '<nmaprun>' + ('x' * 16777217) + '</nmaprun>'
        { Read-ScanXml $xml } | Should Throw 'incomplete or invalid XML'
    }
    It 'withholds IPv4 IPv6 MAC serial certificate headers banners and hostnames' {
        $xml = @'
<nmaprun><host><status state="up"/>
<address addr="192.0.2.77" addrtype="ipv4"/><address addr="2001:db8::77" addrtype="ipv6"/>
<address addr="02:00:00:00:00:77" addrtype="mac" vendor="Apple example-person@example.invalid"/>
<hostnames><hostname name="fictional-private-host.example.invalid"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="http" method="probed" hostname="fictional-private-host.example.invalid" product="SERIAL-FICTIONAL-777" extrainfo="Server: fictional-private-header"/>
<script id="ssl-cert" output="CN=fictional-private-certificate; 203.0.113.77; SERIAL-FICTIONAL-777"/>
<script id="http-headers" output="Server: fictional-private-header"/>
</port></ports></host></nmaprun>
'@
        $text = New-AiReview ([pscustomobject]@{ Devices = @(Read-ScanXml $xml); Notes = @() }) 'Synthetic prompt'
        foreach ($secret in @('192.0.2.77','2001:db8::77','203.0.113.77','02:00:00:00:00:77','fictional-private','SERIAL-FICTIONAL-777','example-person@')) {
            $text.Contains($secret) | Should Be $false
        }
        $text | Should Match 'Apple'
        $text | Should Match 'Open TCP port 443: http'
        $text | Should Match 'identifying details withheld'
    }
    It 'rejects alternative address syntax and all documentation networks as scan targets' {
        $network = [pscustomobject]@{ Address='192.168.1.42'; Prefix=24 }
        foreach ($address in @('192.168.001.10','0xc0a8010a','3232235786','192.0.2.1','198.51.100.1','203.0.113.1')) {
            Test-Target $address $network | Should Be $false
        }
    }
    It 'rejects UNC relative alternate-stream and known synced report paths' {
        foreach ($path in @('\\example.invalid\share\report.txt','relative\report.txt','C:\local\report.txt:stream')) {
            { Assert-LocalReportPath $path } | Should Throw
        }
        $previous = $env:OneDrive
        try {
            $env:OneDrive = Join-Path $TestDrive 'Synthetic Sync'
            { Assert-LocalReportPath (Join-Path $env:OneDrive 'report.txt') } | Should Throw
        } finally { $env:OneDrive = $previous }
    }
    It 'does not display unexpected exception identities' {
        Mock Find-Nmap { throw 'fictional-private-host 192.0.2.77 C:\Users\ExamplePerson' }
        Mock Show-Notice { }
        Start-Guardian
        Assert-MockCalled Show-Notice -Scope It -Times 1 -Exactly -ParameterFilter { $Text -notmatch 'fictional-private|192\.0\.2\.77|ExamplePerson' }
    }
    It 'has no automatic web upload telemetry clipboard or temporary scan file calls' {
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\Guardian.ps1'), [ref]$tokens, [ref]$errors)
        $commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($command in @('Invoke-WebRequest','Invoke-RestMethod','curl','wget','Set-Clipboard','Out-File','Export-Clixml')) {
            ($commands -contains $command) | Should Be $false
        }
        $source = $ast.Extent.Text
        $source | Should Not Match 'HttpClient|WebClient|GetTempFileName|GetTempPath|Send-MailMessage'
        Mock Set-ReviewClipboard { throw 'Automatic clipboard access' }
        Mock Find-Nmap { 'mock' }; Mock Assert-Npcap { }
        Mock Select-Network { [pscustomobject]@{ Index=1; Address='192.168.1.42'; Scope='192.168.1.0/24' } }
        Mock Confirm-Scan { $false }; Mock Get-ScanResults { throw 'Scan after cancellation' }
        Start-Guardian
        Assert-MockCalled Set-ReviewClipboard -Scope It -Times 0 -Exactly
        Assert-MockCalled Get-ScanResults -Scope It -Times 0 -Exactly
    }
}
