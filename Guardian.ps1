# Windows PowerShell 5.1. Dot-source for offline tests; direct execution runs the app.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GuardianRoot = $PSScriptRoot
$script:Ports = '80,81,443,554,8000,8080,8554,8899'

function Show-Notice([string]$Text) {
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Windows.Forms.MessageBox]::Show($Text, 'Home Network Guardian')
}

function Confirm-Scan([object]$Network) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Home Network Guardian - Permission'
    $form.Size = New-Object System.Drawing.Size(560, 360)
    $form.StartPosition = 'CenterScreen'
    $form.AutoScaleMode = 'Dpi'
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 20)
    $label.Size = New-Object System.Drawing.Size(500, 230)
    $label.Text = "Scan only a home network you own or have permission to inspect.`r`n`r`nNetwork: $($Network.Name) ($($Network.Scope))`r`n`r`nGuardian will discover devices and inspect eight common TCP service ports, certificates and advertised streaming commands. No passwords, device changes or video streams. Scanning stops after five minutes.`r`n`r`nResults stay on this computer until you choose to share them. Scan this network?"
    $yes = New-Object System.Windows.Forms.Button
    $yes.Text = 'Scan my network'
    $yes.Size = New-Object System.Drawing.Size(150, 35)
    $yes.Location = New-Object System.Drawing.Point(200, 265)
    $yes.DialogResult = 'OK'
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Size = New-Object System.Drawing.Size(120, 35)
    $cancel.Location = New-Object System.Drawing.Point(370, 265)
    $cancel.DialogResult = 'Cancel'
    $form.Controls.AddRange(@($label, $yes, $cancel))
    $form.AcceptButton = $yes
    $form.CancelButton = $cancel
    try { return $form.ShowDialog() -eq 'OK' } finally { $form.Dispose() }
}

function Get-PrivateScope([string]$Address, [int]$Prefix) {
    $ip = $null
    if ($Address -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$' -or -not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $Prefix -lt 8 -or $Prefix -gt 32) { throw 'Invalid private IPv4 network.' }
    $b = $ip.GetAddressBytes()
    $private = ($b[0] -eq 10 -and $Prefix -ge 8) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31 -and $Prefix -ge 12) -or
        ($b[0] -eq 192 -and $b[1] -eq 168 -and $Prefix -ge 16)
    if (-not $private) { throw 'Only private local IPv4 networks are allowed.' }
    $bits = [Math]::Max(24, $Prefix)
    $size = [int][Math]::Pow(2, 32 - $bits)
    $base = [int]([Math]::Floor($b[3] / $size) * $size)
    if ($bits -lt 31 -and ($b[3] -eq $base -or $b[3] -eq ($base + $size - 1))) { throw 'Invalid host address.' }
    return "$($b[0]).$($b[1]).$($b[2]).$base/$bits"
}

function Get-NetworkRows {
    foreach ($adapter in @(Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up')) {
        foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource })) {
            [pscustomobject]@{ Index = $adapter.ifIndex; Name = $adapter.Name; Description = $adapter.InterfaceDescription
                Hardware = $adapter.HardwareInterface; Address = $ip.IPAddress; Prefix = $ip.PrefixLength }
        }
    }
}

function Select-Network {
    $candidates = @()
    foreach ($row in @(Get-NetworkRows)) {
        try { $scope = Get-PrivateScope $row.Address $row.Prefix } catch { continue }
        # VPN/virtual connections count as ambiguity, never silently ignored.
        $candidates += [pscustomobject]@{ Index = $row.Index; Name = $row.Name; Address = $row.Address
            Prefix = $row.Prefix; Scope = $scope; Hardware = $row.Hardware; Description = $row.Description }
    }
    if ($candidates.Count -ne 1 -or -not $candidates[0].Hardware -or
        ($candidates[0].Name + ' ' + $candidates[0].Description) -match 'vpn|virtual|hyper-v|vmware|vethernet|wireguard|tunnel|tap|tailscale|zerotier|loopback|wsl|docker|ppp') {
        throw 'Cannot safely select one home network. Connect to home Wi-Fi or Ethernet, disconnect VPNs and unused network connections, then try again. Nothing was scanned.'
    }
    return $candidates[0]
}

function Find-Nmap {
    $command = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { $path = Join-Path $root 'Nmap\nmap.exe'; if (Test-Path -LiteralPath $path -PathType Leaf) { return $path } }
    }
    throw 'Nmap is missing. Install Nmap with its Npcap option from https://nmap.org/download.html, then try again. Guardian installs nothing automatically.'
}

function Assert-Npcap {
    if (-not (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
        throw 'Npcap is missing. Re-run the official Nmap installer with Npcap selected. If it is restricted to administrators, ask a trusted administrator for help. Guardian does not elevate itself or change policy.'
    }
}

function Test-Target([string]$Target, [object]$Network) {
    $scope = Get-PrivateScope $Network.Address $Network.Prefix
    $ip = $null
    if ($Target -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$' -or -not [Net.IPAddress]::TryParse($Target, [ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    try {
        $prefix = [int]($scope.Split('/')[1])
        return (Get-PrivateScope $Target $prefix) -eq $scope
    } catch { return $false }
}

function New-NmapArguments([object]$Network, [string]$Target = '') {
    $scope = Get-PrivateScope $Network.Address $Network.Prefix
    $common = @('-n', '-S', $Network.Address, '-oX', '-')
    if (-not $Target) { return @('-sn') + $common + @($scope) }
    if (-not (Test-Target $Target $Network)) { throw 'Refusing an out-of-scope target.' }
    return @('-sT', '-sV', '--version-intensity', '0', '-Pn', '-p', $script:Ports,
        '--script', 'ssl-cert,rtsp-methods', '--script-timeout', '10s', '--host-timeout', '45s',
        '--max-retries', '1', '--max-rate', '10', '--scan-delay', '100ms', '--max-hostgroup', '1') + $common + @($Target)
}

function New-ScanProcess([object]$Info) {
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $Info
    return $process
}

function Invoke-Nmap([string]$Executable, [string[]]$Arguments, [int]$TimeoutMs) {
    $processWatch = [Diagnostics.Stopwatch]::StartNew()
    if ($TimeoutMs -le 0) { throw 'Scanning deadline reached.' }
    # All arguments are generated numeric scopes/addresses or fixed flags. The
    # executable path is separate, so Program Files paths require no shell quoting.
    if (@($Arguments | Where-Object { $_ -notmatch '^[a-zA-Z0-9.,:/_-]+$' }).Count) { throw 'Invalid scanner argument.' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = $Arguments -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-ScanProcess $info
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Could not start Nmap.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $waitMs = [Math]::Max(0, $TimeoutMs - [int]$processWatch.ElapsedMilliseconds)
        if (-not $process.WaitForExit($waitMs)) { throw 'Nmap timed out; completed device results were retained.' }
        [void]$process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'Nmap failed. Check the Nmap/Npcap installation and permissions. No raw scanner messages are exported.' }
        return $stdout.GetAwaiter().GetResult()
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $process.Kill()
                if (-not $process.WaitForExit(5000)) { throw 'Process did not stop.' }
            }
        } catch { $script:ScanTerminationFailed = $true }
        $process.Dispose()
        $processWatch.Stop()
    }
}

function Read-ScanXml([string]$Text) {
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Ignore
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($Text)), $settings)
        $doc = New-Object Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
        if ($doc.DocumentElement.Name -ne 'nmaprun') { throw 'Wrong XML root.' }
        $finished = $doc.SelectSingleNode('/nmaprun/runstats/finished')
        if ($finished -and $finished.GetAttribute('exit') -eq 'error') { throw 'Incomplete scan.' }
        $devices = @()
        foreach ($hostNode in $doc.SelectNodes('/nmaprun/host')) {
            $status = $hostNode.SelectSingleNode('status')
            if (-not $status -or $status.GetAttribute('state') -ne 'up') { continue }
            $addresses = @($hostNode.SelectNodes('address[@addrtype="ipv4"]') | ForEach-Object { $_.GetAttribute('addr') })
            $vendors = @($hostNode.SelectNodes('address[@addrtype="mac"]') | ForEach-Object { $_.GetAttribute('vendor') })
            $ports = @()
            foreach ($node in $hostNode.SelectNodes('ports/port[state/@state="open"]')) {
                $number = 0
                if (-not [int]::TryParse($node.GetAttribute('portid'), [ref]$number) -or $number -lt 1 -or $number -gt 65535) { throw 'Invalid port.' }
                $service = $node.SelectSingleNode('service')
                $name = ''; $method = ''
                if ($service) { $name = $service.GetAttribute('name'); $method = $service.GetAttribute('method') }
                $ports += [pscustomobject]@{ Number = $number; Protocol = $node.GetAttribute('protocol'); Service = $name; Method = $method
                    Certificate = ($null -ne $node.SelectSingleNode('script[@id="ssl-cert"]'))
                    Rtsp = ($null -ne $node.SelectSingleNode('script[@id="rtsp-methods"]')) }
            }
            $devices += [pscustomobject]@{ Addresses = $addresses; Vendors = $vendors; Ports = $ports; Check = 'Not inspected' }
        }
        return $devices
    } catch { throw 'Nmap returned incomplete or invalid XML. No missing results should be interpreted as absence of devices or services.' }
    finally { if ($reader) { $reader.Dispose() } }
}

function Get-ScanElapsed([object]$Watch) { return [int]$Watch.ElapsedMilliseconds }

function Get-ScanResults([string]$Executable, [object]$Network) {
    $script:ScanTerminationFailed = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $devices = @(); $notes = @()
    try {
        $xml = Invoke-Nmap $Executable (New-NmapArguments $Network) 120000
        $devices = @(Read-ScanXml $xml)
        foreach ($device in $devices) { $device.Ports = @(); $device.Check = 'Incomplete: not yet inspected' }
        $seen = @{}
        foreach ($device in $devices) {
            $device.Check = 'Incomplete: no eligible responding IPv4 target'
            foreach ($target in $device.Addresses) {
                if (-not (Test-Target $target $Network)) { throw 'Discovery returned an out-of-scope address; remaining checks stopped.' }
                if ($seen.ContainsKey($target)) { continue }
                $seen[$target] = $true
                $remaining = 300000 - (Get-ScanElapsed $watch)
                if ($remaining -le 0) { $device.Check = 'Incomplete: five-minute deadline reached'; continue }
                try {
                    $xml = Invoke-Nmap $Executable (New-NmapArguments $Network $target) ([Math]::Min(60000, $remaining))
                    $matches = @(Read-ScanXml $xml | Where-Object { $_.Addresses -contains $target })
                    if ($matches.Count -ne 1) { throw 'No matching responding device.' }
                    $device.Ports = @($matches[0].Ports | Where-Object { $_.Protocol -eq 'tcp' -and $_.Number -in @(80,81,443,554,8000,8080,8554,8899) })
                    $device.Check = 'Service process completed; individual probes may be incomplete or timed out'
                } catch { $device.Check = 'Incomplete: service check failed or timed out; discovery retained' }
                if ($script:ScanTerminationFailed) { throw 'Unable to terminate scan; stop further work.' }
            }
        }
    } catch { $notes += 'Discovery failed, returned invalid data, or scope validation stopped scanning. Only completed results appear below. Check Nmap/Npcap and network permissions.' }
    finally { $watch.Stop() }
    if ((Get-ScanElapsed $watch) -ge 300000) { $notes += 'Five-minute scanning deadline reached. Remaining devices were not inspected.' }
    if ($script:ScanTerminationFailed) { $notes += 'Windows prevented stopping an Nmap process. No further scans were started. Ask a trusted administrator to stop Nmap before retrying.' }
    return [pscustomobject]@{ Devices = $devices; Notes = $notes }
}

function New-AiReview([object]$Results, [string]$Prompt) {
    $lines = @($Prompt.Trim(), '', 'REVIEW BEFORE SHARING',
        'Guardian generated this file locally and has not uploaded it. Copying into an external AI service shares the selected information with that service. Review and edit before sharing.',
        'Addresses, MACs, hostnames, serial numbers, titles and raw banners are omitted. Counts and service combinations may still reveal household information. Synced folders can upload files independently.',
        '', 'NETWORK FINDINGS', "Total discovered devices: $(@($Results.Devices).Count)",
        'These are responding scan records, not a verified count of unique physical devices. Sleeping or filtered devices may be missed.')
    $lines += @($Results.Notes)
    $manufacturers = @('Espressif','Apple','Samsung','Intel','Microsoft','Google','Amazon','Cisco','TP-Link','Netgear','Ubiquiti','ASUSTek','D-Link','Linksys','HP','Hewlett Packard','Brother','Canon','Epson','Raspberry Pi','Sony','LG','Philips','Tuya','Shelly','Hikvision','Dahua','Axis','Synology','QNAP','Dell','Lenovo')
    $services = @('http','https','ssl/http','rtsp','rtsps','upnp','mqtt','mqtts')
    $index = 0
    foreach ($device in $Results.Devices) {
        $index++
        $clues = @($manufacturers | Where-Object { $label = $_; @($device.Vendors | Where-Object { $_ -match ('(?<!\w)' + [regex]::Escape($label) + '(?!\w)') }).Count -gt 0 })
        $vendor = 'Not reported or withheld for privacy'
        if ($clues.Count) { $vendor = $clues -join ', ' }
        $lines += @('', "Device $index", "Manufacturer clues (reported, not verified): $vendor", "Check coverage: $($device.Check)")
        if (-not @($device.Ports).Count) { $lines += 'No confirmed open ports reported in the completed data. This does not prove services are absent.' }
        foreach ($port in $device.Ports) {
            if ($port.Protocol -ne 'tcp' -or $port.Number -notin @(80,81,443,554,8000,8080,8554,8899)) { continue }
            $service = 'Unidentified or withheld for privacy'
            if ($port.Service -in $services) { $service = $port.Service.ToLowerInvariant() }
            $basis = 'Unconfirmed label: detection method not supplied'
            if ($port.Method -eq 'probed') { $basis = 'Response-based identification reported by Nmap; not independently verified' }
            if ($port.Method -eq 'table') { $basis = 'Port-based guess only; service not confirmed' }
            $lines += "Open TCP port $($port.Number): $service. $basis."
            if ($port.Certificate) { $lines += 'TLS certificate information returned; identifying details withheld. Certificate trust and ownership were not verified.' }
            if ($port.Rtsp) { $lines += 'RTSP capability information returned. No playback or stream enumeration was requested.' }
        }
    }
    $lines += @('', 'LIMITATIONS AND NEXT STEPS',
        'Only TCP ports 80,81,443,554,8000,8080,8554,8899 were eligible for service inspection. Missing responses may reflect timeouts or filtering. A completed process does not mean every probe succeeded.',
        'Manufacturers alone do not establish device type. RTSP can indicate streaming, not confirmed camera hardware. Unknown does not mean malicious. No brand, model, ownership or security verdict is verified.',
        'Compare household electronics and the router connected-device list. Check official manufacturer apps, or ask someone trusted to help. Do not change or block unfamiliar devices based only on these clues.')
    return ($lines -join "`r`n") + "`r`n"
}

function Assert-LocalReportPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.IndexOf(':', 2) -ge 0) { throw 'Reports require a local drive path.' }
    $full = [IO.Path]::GetFullPath($Path)
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Reports require a fixed local drive.' }
    foreach ($syncRoot in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial)) {
        if ($syncRoot) {
            $sync = [IO.Path]::GetFullPath($syncRoot).TrimEnd('\')
            if ($full.Equals($sync, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($sync + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Reports cannot be saved inside OneDrive.' }
        }
    }
    $itemPath = $full
    while ($itemPath) {
        if (Test-Path -LiteralPath $itemPath) {
            $item = Get-Item -LiteralPath $itemPath -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reports cannot use linked or redirected folders or files.' }
        }
        $itemPath = [IO.Path]::GetDirectoryName($itemPath)
    }
}

function Save-Review([string]$Text) {
    $directory = Join-Path $env:LOCALAPPDATA 'HomeNetworkGuardian'
    $output = Join-Path $directory 'AI_Review.txt'
    Assert-LocalReportPath $output
    [void][IO.Directory]::CreateDirectory($directory)
    Assert-LocalReportPath $output
    [IO.File]::WriteAllText($output, $Text, (New-Object Text.UTF8Encoding($true)))
    return $output
}

function Open-Review([string]$Path) {
    Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') -ArgumentList ('"' + $Path + '"') -ErrorAction Stop
}

function Set-ReviewClipboard([string]$Text) {
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'Clipboard access requires Windows PowerShell in STA mode. Use Start Guardian.bat or powershell.exe -STA.'
    }
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Clipboard]::SetText($Text)
}

function Copy-Review([string]$Path, [scriptblock]$ClipboardWriter) {
    try {
        # Read the saved file in full, including the prompt and partial-scan notes.
        $text = [IO.File]::ReadAllText($Path)
        if ($ClipboardWriter) { & $ClipboardWriter $text }
        else { Set-ReviewClipboard $text }
        return 'Copied successfully. Paste into your preferred AI assistant.'
    } catch {
        return 'Could not copy the report. The file or Windows clipboard may be unavailable. Try again, or use Open Report to review and copy it in Notepad.'
    }
}

function New-ResultsWindow([string]$Path, [int]$DeviceCount) {
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw 'The results window requires STA mode. Use Start Guardian.bat or powershell.exe -STA.'
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    try {
        $form.Text = 'Home Network Guardian - Results'
        $form.StartPosition = 'CenterScreen'
        $form.AutoScaleMode = 'Font'
        $form.Font = New-Object System.Drawing.Font('Segoe UI', 11)
        $form.ClientSize = New-Object System.Drawing.Size(620, 450)
        $form.MinimumSize = $form.Size
        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.Padding = New-Object System.Windows.Forms.Padding(20)
        $layout.ColumnCount = 1
        $layout.AutoScroll = $true
        $layout.RowCount = 6
        $form.Controls.Add($layout)
        $messages = @(
            'Network scan completed',
            "Devices discovered: $DeviceCount (responding scan records; devices may be missed).",
            'Your results are ready to review with an AI assistant. Open Report to review the findings and any incomplete checks or timeouts before sharing.',
            'Pasting the report into an AI assistant shares the selected information externally. Windows clipboard history or syncing may also retain copied information if enabled. Nothing is copied until you click Copy for AI.'
        )
        foreach ($message in $messages) {
            $label = New-Object System.Windows.Forms.Label
            $label.Text = $message
            $label.AutoSize = $true
            $label.MaximumSize = New-Object System.Drawing.Size(560, 0)
            $label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 16)
            $layout.Controls.Add($label)
        }
        $layout.Controls[0].Font = New-Object System.Drawing.Font('Segoe UI', 16, ([System.Drawing.FontStyle]::Bold))
        $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
        $buttons.AutoSize = $true
        $buttons.Dock = 'Fill'
        $copy = New-Object System.Windows.Forms.Button
        $copy.Name = 'CopyForAI'
        $copy.Text = '&Copy for AI'
        $copy.Font = New-Object System.Drawing.Font($form.Font, ([System.Drawing.FontStyle]::Bold))
        $open = New-Object System.Windows.Forms.Button
        $open.Name = 'OpenReport'
        $open.Text = '&Open Report'
        $close = New-Object System.Windows.Forms.Button
        $close.Name = 'CloseResults'
        $close.Text = 'C&lose'
        $close.DialogResult = 'Cancel'
        $index = 0
        foreach ($button in @($copy, $open, $close)) {
            $button.AutoSize = $true
            $button.MinimumSize = New-Object System.Drawing.Size(160, 44)
            $button.TabIndex = $index++
            $buttons.Controls.Add($button)
        }
        $layout.Controls.Add($buttons)
        $status = New-Object System.Windows.Forms.Label
        $status.Name = 'CopyStatus'
        $status.AutoSize = $true
        $status.MaximumSize = New-Object System.Drawing.Size(560, 0)
        $status.AccessibleName = 'Report action status'
        $layout.Controls.Add($status)
        # GetNewClosure retains variables, not the caller's function scope.
        # Keep the actual function bodies and pass the clipboard dependency
        # explicitly; callbacks need no Guardian function-name lookup later.
        $copyAction = ${function:Copy-Review}
        $clipboardAction = ${function:Set-ReviewClipboard}
        $openAction = ${function:Open-Review}
        $copy.Add_Click({
            try { $status.Text = & $copyAction $Path $clipboardAction }
            catch { $status.Text = 'Could not copy the report. Try again, or use Open Report to copy it in Notepad.' }
        }.GetNewClosure())
        $open.Add_Click({
            try { & $openAction $Path }
            catch { $status.Text = "Your review was saved, but Notepad could not open. Try again or open this file manually: $Path" }
        }.GetNewClosure())
        $form.CancelButton = $close
        # No default Copy action: copying always requires an explicit button action.
        $form.ActiveControl = $copy
        return $form
    } catch { $form.Dispose(); throw }
}

function Show-Results([string]$Path, [int]$DeviceCount) {
    $form = New-ResultsWindow $Path $DeviceCount
    try { [void]$form.ShowDialog() } finally { $form.Dispose() }
}

function Start-Guardian {
    try {
        $executable = Find-Nmap
        Assert-Npcap
        $network = Select-Network
        if (-not (Confirm-Scan $network)) { return }
        $current = Select-Network
        if ($current.Index -ne $network.Index -or $current.Address -ne $network.Address -or $current.Scope -ne $network.Scope) {
            throw 'Network settings changed. Run Guardian again to review the new network. Nothing was scanned.'
        }
        $prompt = [IO.File]::ReadAllText((Join-Path $script:GuardianRoot 'AI_Prompt.txt'))
        $results = Get-ScanResults $executable $network
        $output = Save-Review (New-AiReview $results $prompt)
        try { Show-Results $output @($results.Devices).Count }
        catch {
            try { Open-Review $output } catch { Show-Notice "Your review was saved, but Notepad could not open. Open this file manually: $output" }
        }
    } catch {
        # Only application-authored guidance may reach the UI. OS exceptions can
        # contain usernames, paths, scanner diagnostics or network identifiers.
        $message = 'Guardian could not complete this run. Check local report-folder access, Nmap/Npcap and network permissions. No raw error details are displayed.'
        foreach ($prefix in @('Nmap is missing.', 'Npcap is missing.', 'Cannot safely select one home network.', 'Network settings changed.')) {
            if ($_.Exception.Message.StartsWith($prefix, [StringComparison]::Ordinal)) { $message = $_.Exception.Message; break }
        }
        Show-Notice $message
    }
}

if ($MyInvocation.InvocationName -ne '.') { Start-Guardian }
