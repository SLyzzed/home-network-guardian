# Home Network Guardian

A free, open-source, local-first Windows application in development, helping
people identify home network devices through accessible, plain-English explanations.

Phase 1 provides a Python analysis library. A Windows interface and automatic
discovery are future work. This library reads existing Nmap `-oX` XML files;
it does not run scans, upload data, or require Nmap to parse saved results.

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
| Possible camera or streaming device | Open RTSP/RTSPS service | Potential video streaming; never confirmation of a camera |
| Likely networking equipment | Open DNS (`domain`) or DHCP service | Computers can also provide these services |
| Other identified device | Reported manufacturer or hostname | An identity clue, not a verified device type |
| Unknown device | Insufficient identity or service clues | Unidentified does not mean suspicious or malicious |

Port numbers alone do not determine device type. Espressif hardware alone does
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

Open `report.html` in a browser. Each device includes a suggested category,
scan-reported details, clearly separated assumptions, and plain-English
limitations. Missing information and empty scans are explained without implying
safety or danger. The report uses semantic headings, readable text, a responsive
layout, and print styles. It has no scripts, remote assets, or runtime dependencies.
Each device has a clearly labelled **Plain-English explanation** describing what
the clues suggest, with assumptions distinguished from scan observations and
limitations shown alongside the explanation.
Suggested next steps are tailored to the classification: compare devices you
recognize, use official apps or instructions, review updates and sharing where
appropriate, and seek trusted help for unfamiliar devices. Guidance recommends
identifying a device before blocking it or changing settings and acknowledges
that changes may affect personal safety on a network controlled by someone else.
Every report, including an empty one, explains the limits of network discovery:
scan scope, sleeping or unresponsive devices, separate networks, changing addresses,
possible duplicate records, uncertain identity clues, and the inability to prove
security, camera presence, recording activity, or device ownership.
For nontechnical readers, the report includes a short reading guide, an optional
plain-language glossary, and explanations of services and ports. Raw scan status
and response codes sit in an optional technical-details section.
All scan text is escaped as text, including hostnames and service details.
The report prominently displays **Total discovered devices**, counting supplied
device records once each, regardless of address count or response status. It
explains that this is not a live count of connected devices.

`generate_html_report(devices)` returns HTML without writing a file.
`write_html_report(devices, path)` saves UTF-8 HTML, replaces an existing file at
that path, and propagates filesystem errors as `OSError`. Both accept an optional
`title` keyword. Reports contain network identifiers, so share them thoughtfully.

Licensed under the MIT licence; see [LICENSE](LICENSE).
