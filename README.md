# Home Network Guardian

A free, open-source Windows tool that helps you collect privacy-filtered clues about devices on your home network. No Python, accounts, subscriptions, or AI integration.

## Use it

1. Install **Nmap for Windows**, including its **Npcap** option, from https://nmap.org/download.html. Guardian does not install software for you.
2. Extract the Guardian folder. Keep **Start Guardian.bat**, **Guardian.ps1**, and **AI_Prompt.txt** together.
3. Connect to your home Wi-Fi or Ethernet. Disconnect VPNs and unused network connections.
4. Double-click **Start Guardian.bat**. Read the permission dialog. Choose **Scan my network** only if you own or have permission to inspect that network. Choose **Cancel** to stop without scanning.
5. Wait up to five minutes for scanning. A results popup shows the discovered device count and provides **Copy for AI**, **Open Report**, and **Close** buttons.
6. Choose **Open Report** to review the saved text in Notepad. **Copy for AI** copies the complete saved report, including its AI prompt and scan evidence. Paste it into your preferred AI assistant yourself. If you edit the report in Notepad, save before using Copy for AI.

The file is saved in **%LOCALAPPDATA%\HomeNetworkGuardian\AI_Review.txt**. To find it manually, paste that folder path into File Explorer. Each completed run replaces the previous file. No raw scan files are saved.

**Pasting into an AI service shares the selected information with that service.** Guardian itself never uploads anything or connects to AI services. Nothing is copied until you activate Copy for AI, and no website opens automatically. Windows clipboard history or syncing may retain copied information if enabled. The app works without an AI account. Its output is also readable without AI.

## If something goes wrong

- **Nmap or Npcap missing:** re-run the official Nmap installer and select Npcap. Installation may require administrator assistance. Guardian does not elevate itself.
- **More than one network or no suitable network:** disconnect VPNs and unused adapters, connect to your home network, and try again. Guardian does not guess which network you meant.
- **Windows blocks the script:** do not disable security policies. Ask a trusted administrator to review and approve the files. Organisation-managed devices may prohibit this tool. A failed launcher may show a console message so the error remains visible.
- **Scanning errors or timeout:** completed device results are retained where available. Read the incomplete-check notes. A timed-out discovery cannot reliably recover devices from truncated XML.
- **Results popup unavailable:** Guardian opens the saved report in Notepad instead.
- **Clipboard unavailable:** the popup explains the problem; retry or use Open Report to copy manually.
- **Notepad does not open:** a message shows where the file was saved. Open it yourself with a text editor.

## What is checked

One connected physical private IPv4 network is eligible: 10.x.x.x, 172.16.x.x through 172.31.x.x, or 192.168.x.x. The automatic scope never exceeds 256 addresses; larger subnets are restricted to the containing /24. Network settings are checked again after consent.

One permission covers discovery and limited service inspection. Only responding discovered addresses are inspected, sequentially, on TCP ports **80,81,443,554,8000,8080,8554,8899**. Nmap uses lightweight service detection (intensity 0), one retry, a scan rate cap of 10 packets/second, and a 100ms scan delay. These scan controls are not a strict cap on all service/script traffic. Only the explicitly selected `ssl-cert` and `rtsp-methods` scripts are requested. Guardian does not request passwords, authentication, vulnerabilities, stream URLs, or video playback. No devices are blocked or changed.

Discovery has a 120-second process timeout; each service process has at most 60 seconds, a 45-second host timeout, and a 10-second script timeout. All scanning shares a five-minute deadline. Timed-out Nmap processes are terminated, with up to five seconds allowed for termination. No further scans start if termination fails; the report explains that administrator help is needed. Report writing and opening Notepad happen after scanning and are outside that deadline.

## Privacy and limitations

Devices are numbered. IP addresses, MAC addresses, hostnames, serial numbers, certificate identities, and raw service banners are not included. Manufacturer clues are reduced to a small recognised-name vocabulary; unfamiliar names are withheld. Raw certificate and RTSP output are replaced by presence statements. This conservative filtering loses detail, but avoids copying hidden personal identifiers. Counts and service combinations may still reveal household information. File-sync software can upload files independently of Guardian.

Nmap response-based identification is distinguished from port-based guesses. Neither is independently verified. Manufacturers do not establish device type; RTSP does not confirm camera hardware or recording. Unknown does not mean malicious. Sleeping devices, firewalls, guest networks, larger subnets and uncommon ports can hide devices or services. Completed processes may still contain individual probe timeouts. No result establishes that your network is safe or unsafe.

The prepared prompt asks for plain-English explanations, evidence-based possibilities, alternative explanations, safe next steps, and optional public manufacturer research with reliable sources. An AI response is advice to review, not verified identification. No public research is performed by Guardian.

## Developer validation

To test the results popup with the existing saved report without running a scan:

```powershell
powershell.exe -NoProfile -STA -File .\tools\Show-SavedReport.ps1
```

You can also pass `-Path "C:\local-folder\AI_Review.txt"`. This reads the device count from the report and displays the same popup without saving, scanning, or automatically copying. Copy for AI reads the complete file when clicked and shows **Copied successfully**. Close or Escape dismisses the popup. A missing or unreadable report produces a plain-English message.

Runtime: Windows PowerShell 5.1 and Windows networking cmdlets; Nmap/Npcap are separate prerequisites. The launcher does not bypass execution policy, change machine settings, download dependencies, or request elevation. It uses built-in permission/error dialogs, not a separate GUI application.

Tests use **Pester 3.4 or 4.x**, with Nmap and Notepad side effects mocked. Windows Forms tests display and automatically close real popups; run in an interactive Windows desktop session. A separate-process regression test removes the original Guardian function scope, clicks every button, checks the entire actual clipboard text (including Unicode and a long synthetic report), and restores the previous clipboard data. Only synthetic text is copied; Windows clipboard history or syncing may retain it if enabled. Other tests simulate clipboard/Notepad failures and reject non-STA access. Pester is only a developer dependency. Run from the repository folder:

```powershell
powershell.exe -NoProfile -STA -File .\tests\Run-Tests.ps1
powershell.exe -NoProfile -File .\samples\Generate-Example.ps1
```

The second command generates **samples\AI_Review.example.txt** from synthetic XML only. It does not scan or launch Notepad. Tests cover scope, consent, commands, deadlines, process cleanup, parsing, redaction, output, and Notepad invocation. Generated private reports and scan files are ignored; only named synthetic fixtures and the synthetic text example are retained. Never force-add real scan results.

Before distribution, manually validate on Windows with Nmap/Npcap: cancellation, an authorised real scan, Notepad launch, an installation path containing spaces, missing prerequisites, ambiguous networks, and blocked-script behavior. Test display scaling and keyboard access. Distribution may require signing and organisational approval; the tool never bypasses those requirements.

MIT licensed. See [LICENSE](LICENSE).

## Distribution and storage safeguards

Build the end-user ZIP with `powershell.exe -NoProfile -File .\tools\Build-Release.ps1`.
The verified allowlist includes only Start Guardian.bat, Guardian.ps1, AI_Prompt.txt,
README.md and LICENSE. Never ZIP the repository folder: ignored files can include
private reports. Developer tools, fixtures, tests and Git metadata are excluded.

Report saving requires a fixed local drive and rejects UNC paths, alternate data
streams, reparse points (including junctions) and known OneDrive roots. If storage
validation fails, Guardian stops without choosing another folder. Other sync or
backup software cannot be detected reliably; check your own settings. The report
inherits the local user's folder permissions; it is not encrypted. Manually edited
reports and prompts can contain personal data; review them before copying.
