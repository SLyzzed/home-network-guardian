# Home Network Guardian

A free, open-source, local-first Windows application in development, helping
people identify home network devices through accessible, plain-English explanations.

Phase 1 provides a Python analysis library. Phase 2 adds consent-based Windows
network discovery using Nmap. Saved Nmap XML can still be analyzed offline
without installing Nmap. Guardian processes scans locally and does not upload them. Automatic file synchronisation
(such as OneDrive) can copy locally saved reports to cloud storage. Save outside
synced folders if you want reports to remain only on this computer.

## Discover your home network (Windows)

Install Nmap yourself using the Windows installer at https://nmap.org/download.html
with its Npcap option, then reopen PowerShell. Guardian checks PATH and common
Program Files installation directories; it never installs software.

```powershell
uv run python -m guardian scan --output report.html --dry-run
uv run python -m guardian scan --output report.html
```

Review the displayed interface and scan scope. If multiple connected private IPv4
addresses are available, choose your home Wi-Fi or Ethernet from the numbered list.
VPN, virtual, and unverified adapters always require explicit selection. Enter
`yes` at the consent prompt only if you own or have permission to scan that network.
Enter anything else to cancel. Dry run reads local settings and shows the intended
command without invoking Nmap or writing a report. There is no unattended consent
flag, background scan, or scheduled scan.

Only RFC 1918 private IPv4 subnets are eligible (10/8, 172.16/12, 192.168/16).
Public, loopback, link-local, disconnected, and invalid configurations are excluded.
The scope never exceeds 256 addresses: larger subnets are limited to the /24
containing the selected local address; smaller subnets retain their prefix.
There is no arbitrary target/range option. Settings are rechecked after consent.

The Nmap command uses `-sn` for [host discovery](https://nmap.org/book/man-host-discovery.html),
`-n` to disable DNS lookups, the selected local source address, and XML on stdout.
No port/service/vulnerability scans, camera access, credentials, or exploits are used.
XML is parsed in memory by the existing parser and the existing classifier and HTML
writer produce the standalone report. Guardian does not upload results; file-sync software may upload saved files. Existing output files
are replaced. Report totals separate responding records from unidentified records
and possible streaming classifications; unidentified does not mean dangerous.

Limitations: Windows PowerShell networking cmdlets and Nmap/Npcap are required.
Adapter detection is conservative and uses Windows hardware metadata plus name
heuristics; adapter names cannot reliably identify every VPN. Active VPN routing
or overlapping subnets can affect which interface Nmap uses even with a selected
source address; disconnect a VPN before scanning your home network. The scope
can omit most of a large subnet. Discovery may miss sleeping or filtered devices.
It normally provides no hostnames (DNS is disabled) or service evidence, so many
devices will remain unidentified and camera/streaming classification is unlikely.
Detection times out after 20 seconds and discovery after 120 seconds; failures do
not generate a report. No live scan is exercised by the automated tests.

Generated HTML, XML, Nmap outputs, and `scan-results/` are ignored by Git; synthetic
XML fixtures under `samples/` remain available. Keep private results outside that
fixture directory and do not force-add them to Git.

## Development

Requires Python 3.11 or later. From the repository directory in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

Runtime dependencies: Python standard library only. Pytest is a development dependency.

## Use the engine

```python
from guardian import classify_device, parse_nmap_file, NmapParseError

try:
    devices = parse_nmap_file("scan.xml")
except NmapParseError as error:
    print(error)
else:
    for device in devices:
        result = classify_device(device)
        print(device.hostnames or device.ip_addresses or ("Unnamed device",))
        print(result.category.value)
        print(result.explanation)
```

`parse_nmap_xml` also accepts XML text or bytes. Devices retain IPv4 and IPv6
addresses, MAC addresses, manufacturers, hostnames, status and its reason, and
open TCP/UDP ports with available service details. Missing information stays
empty or unknown. Closed, filtered, and `open|filtered` ports are not reported as
confirmed open ports. Malformed XML and invalid open port numbers produce
`NmapParseError`; unreadable files produce the same public error type.

## How classifications work

Rules use reported service names, with the following precedence:

| Category | Evidence | Limitation |
| --- | --- | --- |
| Possible streaming device | Open RTSP/RTSPS service | Potential video streaming; never confirmation of a camera |
| Likely networking equipment | Open DNS (`domain`) or DHCP service | Computers can also provide these services |
| Device type unknown | No supported service evidence for a type, even if a manufacturer or hostname is reported | Names and manufacturers are separate clues, not verified identities; unknown does not mean dangerous |

IP addresses, port numbers, manufacturers, and hostnames alone do not determine
device type. The former `Category.IDENTIFIED` category has been removed; callers
should use `Category.UNKNOWN` for manufacturer-only or name-only records. Espressif hardware alone does
not indicate a camera. All results include reasons and limitations, and none
constitute a safety or threat verdict. Every classification exposes a plain-English
`explanation` combining its reasons and limitations; empty reasons are rejected.
Explanations label `observations` (what the supplied scan reports) separately from
`assumptions` (the rules' interpretation). Observations are not independent
confirmation of a device's identity, behavior, or current state. The category
is an interpretation; reported service names and manufacturer names may be guesses
made by the scanner. `reasons` retains the combined evidence and interpretation.
Scan information can be incomplete,
incorrect, or outdated; hostnames and manufacturers are reported clues.

Application modules live in `src/guardian`: `models.py` holds observations,
`parser.py` reads XML, and `classification.py` explains classification rules.
Tests use synthetic scan data and do not access your network.

## Offline HTML report

Generate a report from the included synthetic scan using the command line:

```powershell
uv run python -m guardian report samples/example_scan.xml --output report.html
```

Supply your own Nmap XML path in place of `samples/example_scan.xml`.
The `--output` option is required; an existing output file is replaced.

```python
from guardian import parse_nmap_file, write_html_report

write_html_report(parse_nmap_file("scan.xml"), "report.html")
```

Open `report.html` in a browser. The opening **At a glance** summary shows record
counts, explains what discovery checks, and gives a concrete first step: compare
your router's connected-device list with devices you own. A manufacturer clue is
shown separately from the suggested device type. Basic discovery does not inspect
ports or services; missing service information never means no services are running.
For imported XML, absence of open ports cannot establish which checks were performed.
The report does not infer scan coverage from missing data or perform extra scans.

Each device has a short explanation, reported observations, one next step, and
optional technical details. Shared explanations and discovery limitations are in
one native expandable help section, available without scripts or an internet
connection. It covers uncertain clues, scan scope, sleeping devices, changing
addresses, possible duplicate records, and limits on security or camera conclusions.
The report uses semantic headings, readable text, responsive layout, and print
styles. Guidance recommends identifying a device before blocking it or changing
settings and seeking trusted help if changes could affect personal safety.

Generate the six-device synthetic discovery example (no real network data):

```powershell
uv run python -m guardian report samples/example_discovery.xml --output synthetic-example-report.html
```

All six records have unknown device types, including those with manufacturer
clues. The existing `samples/example_scan.xml` demonstrates imported service evidence.

All scan text is escaped as text, including hostnames and service details.
The report prominently displays **Total discovered devices**, counting supplied
device records once each, regardless of address count or response status. It
explains that this is not a live count of connected devices.

`generate_html_report(devices)` returns HTML without writing a file.
`write_html_report(devices, path)` saves UTF-8 HTML, replaces an existing file at
that path, and propagates filesystem errors as `OSError`. Both accept an optional
`title` keyword. Reports contain network identifiers, so share them thoughtfully.

Licensed under the MIT licence; see [LICENSE](LICENSE).
