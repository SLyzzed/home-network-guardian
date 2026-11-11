"""Self-contained, escaped HTML reports with no remote resources or scripts."""

from collections.abc import Iterable
from html import escape
from pathlib import Path

from .classification import Category, classify_device
from .models import Device


_SERVICE_EXPLANATIONS = {
    "rtsp": "May support video streaming; this does not confirm a camera.",
    "rtsps": "May support encrypted video streaming; this does not confirm a camera.",
    "domain": "Helps devices look up network addresses (DNS).",
    "dhcp": "Helps devices obtain network settings (DHCP).",
    "dhcps": "Helps devices obtain network settings (DHCP).",
    "bootps": "Helps devices obtain network settings (BOOTP or DHCP).",
    "http": "May provide a web page or browser-based controls.",
    "https": "May provide an encrypted web page or browser-based controls.",
    "ssh": "May provide remote command-line access.",
}


_NEXT_STEPS = {
    Category.NETWORKING: (
        "Compare the reported name and manufacturer with your router, modem, or Wi-Fi equipment.",
        "If you recognize it, check its official app or manufacturer instructions for software updates.",
    ),
    Category.STREAMING: (
        "Compare this device with cameras, doorbells, TVs, and streaming equipment you know about.",
        "If it is yours, use its official app to review sharing settings and software updates.",
        "If it remains unfamiliar, ask someone you trust to help identify it. This scan does not confirm a camera.",
    ),
    Category.UNKNOWN: (
        "Check your router's connected-device list using its official app or instructions, and compare it with devices you own.",
        "Remember that phones, TVs, printers, smart plugs, and visiting devices may use unfamiliar names.",
        "If you still cannot identify it, ask someone you trust for help. Unknown does not mean dangerous.",
    ),
}


def _list(items: Iterable[str]) -> str:
    return "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in items) + "</ul>"


def _device_html(device: Device, number: int) -> str:
    result = classify_device(device)
    name = next(iter(device.hostnames or device.ip_addresses), f"Unnamed device {number}")
    status = {"up": "Responded during the scan", "down": "Did not respond during the scan"}.get(
        device.status, "Response status is unknown")
    details = (
        ("Device IP addresses", ", ".join(device.ip_addresses) or "Not reported"),
        ("Hardware addresses (MAC)", ", ".join(device.mac_addresses) or "Not reported"),
        ("Manufacturer clue (reported by the scan)", ", ".join(device.manufacturers) or "Not reported"),
        ("Reported device names", ", ".join(device.hostnames) or "Not reported"),
        ("Response during scan", status),
        ("Raw scan status", device.status),
        ("Reported response reason", device.status_reason or "Not reported"),
    )
    facts = "".join(f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>" for label, value in details[:5])
    technical_facts = "".join(f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>" for label, value in details[5:])
    ports = []
    for port in device.open_ports:
        service = port.service
        service_details = "; ".join(value for value in (
            service.name, service.product, service.version, service.extra_info,
            f"Tunnel: {service.tunnel}" if service.tunnel else None,
        ) if value) if service else ""
        explanation = _SERVICE_EXPLANATIONS.get(service.name.casefold(), "") if service and service.name else ""
        ports.append(f"Port {port.number} ({port.protocol}): {service_details or 'Service not identified'}"
                     + (f" - {explanation}" if explanation else ""))
    return (
        f'<article aria-labelledby="device-{number}"><h3 id="device-{number}">{escape(name)}</h3>'
        f'<p><strong>Device classification (suggested):</strong> {escape(result.category.value)}</p>'
        '<p><strong>Why:</strong> '
        + escape(" ".join(result.assumptions)) + '</p>'
        + '<h4>Reported observations</h4>'
        + f'<dl>{facts}</dl>'
        '<p><strong>Services:</strong> '
        + ('Open port details are available in the saved scan; service names may be missing.' if ports else
           'No port or service information is available. Basic discovery does not inspect ports or services; this does not mean no services are running.')
        + '</p><h4>Suggested next step</h4>'
        + _list(_NEXT_STEPS[result.category][:1])
        + '<details><summary>Technical scan details (optional)</summary>'
        + f'<dl>{technical_facts}</dl><h4>Relevant services and open ports</h4>'
        + (_list(ports) if ports else '<p>No confirmed open ports were reported.</p>')
        + '</details>'
        + '</article>'
    )


def generate_html_report(devices: Iterable[Device], *, title: str = "Home Network Guardian report") -> str:
    """Return a complete offline HTML document; all scan text is treated as text."""
    devices = tuple(devices)
    unidentified = sum(classify_device(d).category == Category.UNKNOWN for d in devices)
    streaming = sum(classify_device(d).category == Category.STREAMING for d in devices)
    content = "".join(_device_html(device, number) for number, device in enumerate(devices, 1))
    if not devices:
        content = '<p>No devices were included in this scan. This does not mean your network has no connected devices.</p>'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
        f'<title>{escape(title)}</title><style>'
        'body{font:1.125rem/1.6 system-ui,sans-serif;color:#17212b;background:#f4f6f8;margin:0;overflow-wrap:anywhere}'
        'main{max-width:54rem;margin:auto;padding:1.25rem}article{background:#fff;border:1px solid #637381;border-radius:.5rem;padding:1.25rem;margin:1.5rem 0}'
        'h1,h2,h3,h4{line-height:1.3}dt{font-weight:bold}dd{margin:0 0 .75rem}li{margin:.5rem 0}'
        '@media print{body{background:white}main{max-width:none}article{border-color:#555}}'
        '</style></head><body><main>'
        f'<h1>{escape(title)}</h1>'
        '<section aria-labelledby="summary"><h2 id="summary">At a glance</h2>'
        f'<p><strong>Total discovered devices:</strong> <span id="total-devices">{len(devices)}</span>. '
        f'Responded during the scan: {sum(d.status == "up" for d in devices)}. '
        f'Device type unknown: {unidentified}. Possible streaming devices: {streaming}.</p>'
        '<p>These totals count scan records, not verified unique physical devices, and are not a count of devices currently connected.</p>'
        '<p><strong>What was checked:</strong> Device discovery finds devices that reply. '
        'Basic host discovery does not inspect ports or services and cannot tell you what a device does. '
        'Service details appear only when included in a supplied saved scan; this report performs no additional scanning.</p>'
        '<p>A known manufacturer does not identify the device or its type. Unknown does not mean dangerous. '
        'This report cannot determine whether your network is safe.</p>'
        '<p><strong>Start here:</strong> Open your official router app or follow its instructions to find its connected-device list. '
        'Compare that list with devices you own. Ask someone you trust for help with anything unfamiliar.</p>'
        '<p>Identify the device before blocking it or changing settings. If changing settings could '
        'affect your safety or someone else controls the network, seek help from someone you trust first.</p></section>'
        '<p>This file works offline and loads no external resources. It contains private network details. '
        'Guardian does not upload reports, but automatic file synchronisation, such as OneDrive, '
        'can copy locally generated reports to cloud storage. Choose a folder outside synced locations '
        'if you want the report to stay only on this computer, and consider who can access it before sharing.</p>'
        '<section aria-labelledby="devices"><h2 id="devices">Device details</h2>'
        + content + '</section>'
        '<details><summary>Help: discovery, services, and report limitations</summary>'
        '<h2>What do the words in this report mean?</h2><dl>'
        '<dt>IP address</dt><dd>An address used to reach a device on a network. It can change.</dd>'
        '<dt>MAC address</dt><dd>A label used by a device to identify itself on a local network. It can change or be copied.</dd>'
        '<dt>Manufacturer</dt><dd>The company reported as making the device or one of its parts. It may differ from the brand on the box.</dd>'
        '<dt>Classification</dt><dd>A possible device type based on service evidence, or unknown when evidence is insufficient. IP addresses, manufacturers, and names alone do not establish device type.</dd>'
        '<dt>Streaming</dt><dd>Sending or playing video or sound over a network.</dd>'
        '<dt>Firewall</dt><dd>A feature that can block network connections or replies.</dd>'
        '<dt>Service and port</dt><dd>A service is something a device offers over the network; a port is a numbered connection point. TCP and UDP are ways devices send information. Service names are scanner-reported clues; port numbers alone do not confirm a service. An open port does not by itself indicate danger.</dd>'
        '</dl>'
        '<section aria-labelledby="discovery-limitations"><h2 id="discovery-limitations">Limitations of network discovery</h2>'
        + _list((
            "This report is a snapshot of the supplied scan, not a live view. Devices and their addresses can change after a scan.",
            "Discovery can miss devices that are asleep, switched off, disconnected, or configured not to respond. A missing device is not proof that it is absent.",
            "Only the addresses, network areas, and ports covered by the scan can appear here. Guest Wi-Fi, separate networks, and router restrictions can hide devices from a scan.",
            "A device that does not respond is not necessarily switched off. Firewalls and network restrictions can block replies.",
            "One physical device may appear in multiple scan records or use several addresses. Report totals count records, not verified unique physical devices.",
            "Names, manufacturers, and service labels are clues reported by the scanner and may be missing or incorrect. Categories are interpretations, not verified identities.",
            "An open port does not prove a security weakness. No reported open ports does not prove that a device is secure.",
            "Network discovery cannot confirm that a device is a camera, detect every camera, or determine whether a device is recording. Devices on other networks or without a network connection may not appear.",
            "This report cannot prove that a network is safe or unsafe, or determine who owns a device or why it is connected. Unknown devices are not automatically suspicious or malicious.",
        ))
        + '</section>'
        + '</details></main></body></html>'
    )


def write_html_report(devices: Iterable[Device], path: str | Path, *, title: str = "Home Network Guardian report") -> Path:
    """Write UTF-8 HTML to the supplied path and return it. Existing files are replaced.

    Filesystem errors propagate as OSError so callers can explain save failures.
    """
    output = Path(path)
    output.write_text(generate_html_report(devices, title=title), encoding="utf-8")
    return output
