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
    Category.IDENTIFIED: (
        "Compare the reported name and manufacturer with devices you own; these clues may not give the exact model.",
        "If you recognize it, check its official app or manufacturer instructions for software updates.",
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
        ("Identified manufacturers (reported by the scan)", ", ".join(device.manufacturers) or "Not identified"),
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
                     + (f" — {explanation}" if explanation else ""))
    return (
        f'<article aria-labelledby="device-{number}"><h2 id="device-{number}">{escape(name)}</h2>'
        f'<p><strong>Device classification (suggested):</strong> {escape(result.category.value)}</p>'
        '<h3>Reported observations</h3>'
        '<p>These are details saved in the scan. They have not been checked directly against the device.</p>'
        f'<dl>{facts}</dl>'
        '<details><summary>Technical scan details (optional)</summary>'
        f'<dl>{technical_facts}</dl></details>'
        '<h4>Relevant services and open ports</h4>'
        '<p>A service is something a device offers over the network, such as a web page or video stream. '
        'A port is a numbered connection point for a network service. '
        'TCP and UDP are ways devices send information. You do not need to understand these labels to use this report. '
        'All confirmed open ports from the supplied scan are listed below. '
        'Service names are reported by the scanner; port numbers alone do not confirm what a service does. '
        'An open port does not by itself indicate danger.</p>'
        + (_list(ports) if ports else '<p>No confirmed open ports were reported. This does not prove that no services are running.</p>')
        + '<h3>Plain-English explanation</h3>'
        + '<p><strong>Assumptions and interpretation:</strong> This is what the scan clues suggest, '
        'rather than a confirmed device type.</p>'
        + _list(result.assumptions or result.reasons)
        + '<h3>What this cannot tell you</h3>' + _list(result.limitations)
        + '<h3>Suggested next steps</h3>' + _list(_NEXT_STEPS[result.category])
        + '<p>Identify the device before blocking it or changing settings. If changing settings could '
        'affect your safety or someone else controls the network, seek help from someone you trust first.</p>'
        + '</article>'
    )


def generate_html_report(devices: Iterable[Device], *, title: str = "Home Network Guardian report") -> str:
    """Return a complete offline HTML document; all scan text is treated as text."""
    devices = tuple(devices)
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
        '<p>This report helps you recognize devices on your home network, such as phones, TVs, and Wi-Fi equipment. '
        'A scan is a check for devices that can reply over the network.</p>'
        '<p>Start with each device name and suggested type, then read its explanation and next steps. '
        'You do not need to understand network addresses or port numbers.</p>'
        f'<p><strong>Total discovered devices:</strong> <span id="total-devices">{len(devices)}</span></p>'
        '<p>This total counts device records in the supplied scan, including devices that did not respond '
        'or have an unknown response status. It is not a count of devices currently connected.</p>'
        '<p>This report uses a saved scan. Results may be incomplete or outdated. '
        'An unknown device is unidentified; it is not automatically suspicious or malicious. '
        'A possible streaming device is not confirmation of a camera.</p>'
        '<p>This file works offline and loads no external resources. It contains network details; '
        'consider who can access it before sharing.</p>'
        '<details><summary>What do the words in this report mean?</summary><dl>'
        '<dt>IP address</dt><dd>An address used to reach a device on a network. It can change.</dd>'
        '<dt>MAC address</dt><dd>A label used by a device to identify itself on a local network. It can change or be copied.</dd>'
        '<dt>Manufacturer</dt><dd>The company reported as making the device or one of its parts. It may differ from the brand on the box.</dd>'
        '<dt>Classification</dt><dd>A suggested device type based on the available clues.</dd>'
        '<dt>Streaming</dt><dd>Sending or playing video or sound over a network.</dd>'
        '<dt>Firewall</dt><dd>A feature that can block network connections or replies.</dd>'
        '</dl></details>'
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
        + content + '</main></body></html>'
    )


def write_html_report(devices: Iterable[Device], path: str | Path, *, title: str = "Home Network Guardian report") -> Path:
    """Write UTF-8 HTML to the supplied path and return it. Existing files are replaced.

    Filesystem errors propagate as OSError so callers can explain save failures.
    """
    output = Path(path)
    output.write_text(generate_html_report(devices, title=title), encoding="utf-8")
    return output
