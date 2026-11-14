# Home Network Guardian

**v0.1.0** · A free, open-source Windows tool for understanding your home network.

## Project Overview

Home Network Guardian scans your home network for devices and prepares privacy-filtered findings you can review or copy into an AI assistant for a plain-English explanation. It is designed for people with little technical knowledge.

## Features

- One-click Windows network scanning, with your approval before scanning begins.
- Device discovery and limited service checks.
- Privacy-filtered results with personal identifiers removed.
- **Copy for AI** to copy findings and a prepared prompt into your preferred AI assistant.
- No subscriptions or AI API required.

## Requirements

- Windows with Windows PowerShell 5.1.
- [Nmap for Windows](https://nmap.org/download.html), installed with **Npcap** selected.

## Getting Started

1. Download **HomeNetworkGuardian.zip** from the repository's releases.
2. Extract the ZIP and keep the extracted files together.
3. Connect to your home network and double-click **Start Guardian.bat**.
4. Read the permission dialog and choose **Scan my network** to approve the scan.
5. When scanning finishes, click **Copy for AI**.
6. Paste the copied report into your preferred AI assistant.

You can also click **Open Report** to read the findings without AI. The report is saved to `%LOCALAPPDATA%\HomeNetworkGuardian\AI_Review.txt`; each completed run replaces the previous report.

## Privacy and Security

- Scanning and report preparation happen locally on your computer.
- Guardian does not automatically upload results or connect to AI services.
- Personal identifiers, including IP addresses, MAC addresses and hostnames, are excluded from the report prepared for AI. Review the report before sharing it; service details may still reveal information about your household.
- Pasting the report into an AI assistant shares it with that service. Clipboard history, syncing or backup software may retain copies independently of Guardian.
- Only scan networks you own or have permission to inspect.

## Limitations

- Guardian cannot identify every network device; sleeping devices, firewalls and network configuration can limit results.
- It cannot guarantee detection of cameras or confirm that a device is recording.
- AI interpretations may be inaccurate. Results do not guarantee that your network is safe or unsafe.

## Technologies

PowerShell, Windows Batch, Nmap and Npcap.

## Acknowledgements

Home Network Guardian was developed with AI assistance.

## Licence

Released under the [MIT Licence](LICENSE).
