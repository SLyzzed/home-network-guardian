from html.parser import HTMLParser

import pytest

from guardian import Device, Port, Service, generate_html_report, write_html_report


class ReportReader(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.text = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data):
        self.text.append(data)


def test_report_separates_facts_and_interpretation_and_preserves_details():
    device = Device(ip_addresses=("192.0.2.1", "2001:db8::1"),
                    mac_addresses=("AA:BB:CC:DD:EE:FF",), manufacturers=("Example",),
                    hostnames=("Living room",), status="up", status_reason="arp-response",
                    open_ports=(Port(554, "tcp", Service("rtsp", "Streamer", "1.2", "Details", "ssl")),))
    report = ReportReader(generate_html_report([device]))
    text = " ".join(report.text)
    for expected in ("192.0.2.1", "2001:db8::1", "AA:BB:CC:DD:EE:FF", "Example",
                     "Living room", "arp-response", "Responded during the scan", "554",
                     "rtsp", "Streamer", "1.2", "Details", "ssl", "Reported observations",
                     "Assumptions and interpretation", "does not confirm a camera"):
        assert expected in text
    assert "article" in report.tags
    assert ("lang", "en") in report.attributes


def test_untrusted_fields_cannot_create_markup_or_external_requests():
    payload = '<script>alert("x")</script><img src="https://example.com/track">&'
    device = Device(hostnames=(payload,), manufacturers=(payload,), ip_addresses=(payload,),
                    mac_addresses=(payload,), status=payload, status_reason=payload,
                    open_ports=(Port(80, payload, Service(payload, payload, payload, payload, payload)),))
    report = ReportReader(generate_html_report([device], title=payload))
    assert "script" not in report.tags
    assert "img" not in report.tags
    assert not any(key in {"src", "href"} for key, _ in report.attributes)
    assert payload in " ".join(report.text)


@pytest.mark.parametrize("devices, expected", [
    ([], "No devices were included"),
    ([Device()], "No confirmed open ports were reported"),
])
def test_empty_and_missing_information(devices, expected):
    html = generate_html_report(iter(devices))
    assert expected in html
    assert "not automatically suspicious or malicious" in html
    assert "Assumptions and interpretation" in html if devices else "does not mean your network" in html


def test_file_is_utf8_and_save_errors_propagate(tmp_path):
    path = tmp_path / "report.html"
    assert write_html_report([Device(hostnames=("Büro",))], path) == path
    assert "Büro" in path.read_text(encoding="utf-8")
    with pytest.raises(OSError):
        write_html_report([], tmp_path / "missing" / "report.html")


@pytest.mark.parametrize("count", [0, 1, 3])
def test_total_counts_device_records_not_addresses_or_response_status(count):
    devices = [
        Device(ip_addresses=("192.0.2.1", "2001:db8::1"), status="up"),
        Device(status="down"),
        Device(),
    ][:count]
    html = generate_html_report(iter(devices))
    assert f'Total discovered devices:</strong> <span id="total-devices">{count}</span>' in html
    assert html.count('<article ') == count
    assert "not a count of devices currently connected" in html


def test_each_device_lists_all_ips_and_manufacturers_or_missing_information():
    html = generate_html_report([
        Device(ip_addresses=("192.0.2.10", "2001:db8::10"),
               manufacturers=("Example Hardware", "Example Components")),
        Device(),
    ])
    first, second = html.split('<article ')[1:]
    assert '<dt>Device IP addresses</dt><dd>192.0.2.10, 2001:db8::10</dd>' in first
    assert '<dt>Identified manufacturers (reported by the scan)</dt><dd>Example Hardware, Example Components</dd>' in first
    assert '<dt>Device IP addresses</dt><dd>Not reported</dd>' in second
    assert '<dt>Identified manufacturers (reported by the scan)</dt><dd>Not identified</dd>' in second


@pytest.mark.parametrize("device, category", [
    (Device(open_ports=(Port(53, "udp", Service("domain")),)), "Likely networking equipment"),
    (Device(open_ports=(Port(554, "tcp", Service("rtsp")),)), "Possible camera or streaming device"),
    (Device(manufacturers=("Example Hardware",)), "Other identified device"),
    (Device(), "Unknown device"),
])
def test_report_includes_device_classification_with_explanation(device, category):
    html = generate_html_report([device])
    assert f'<strong>Device classification (suggested):</strong> {category}' in html
    assert "Assumptions and interpretation" in html
    assert "What this cannot tell you" in html
    assert "<h3>Plain-English explanation</h3>" in html
    assert "<h3>Suggested next steps</h3>" in html
    assert "Identify the device before blocking it" in html


@pytest.mark.parametrize("device, guidance", [
    (Device(), "Unknown does not mean dangerous"),
    (Device(manufacturers=("Example",)), "may not give the exact model"),
    (Device(open_ports=(Port(53, "udp", Service("domain")),)), "router, modem, or Wi-Fi equipment"),
    (Device(open_ports=(Port(554, "tcp", Service("rtsp")),)), "This scan does not confirm a camera"),
])
def test_next_steps_are_tailored_and_do_not_require_command_line_knowledge(device, guidance):
    html = generate_html_report([device])
    assert guidance in html
    assert "seek help from someone you trust first" in html


@pytest.mark.parametrize("devices", [[], [Device()]])
def test_discovery_limitations_are_present_even_without_devices(devices):
    html = generate_html_report(devices)
    assert '<h2 id="discovery-limitations">Limitations of network discovery</h2>' in html
    for limitation in (
        "not a live view", "asleep", "Guest Wi-Fi", "Firewalls",
        "not verified unique physical devices", "may be missing or incorrect",
        "does not prove that a device is secure", "determine whether a device is recording",
        "cannot prove that a network is safe or unsafe",
    ):
        assert limitation in html


def test_nontechnical_reading_guidance_and_optional_jargon_help():
    html = generate_html_report([Device()])
    assert "Start with each device name and suggested type" in html
    assert "You do not need to understand network addresses or port numbers" in html
    assert "<summary>What do the words in this report mean?</summary>" in html
    for term in ("IP address", "MAC address", "Manufacturer", "Classification", "Streaming", "Firewall"):
        assert f"<dt>{term}</dt><dd>" in html
    assert "<summary>Technical scan details (optional)</summary>" in html
    assert "A service is something a device offers" in html


def test_services_and_ports_include_protocol_details_and_cautious_context():
    html = generate_html_report([Device(open_ports=(
        Port(8554, "tcp", Service("RTSP", "Streamer", "2.0")),
        Port(53, "udp", Service("domain")),
        Port(554, "tcp"),
        Port(12345, "tcp", Service("custom-service")),
    ))])
    assert "Relevant services and open ports" in html
    assert "Port 8554 (tcp): RTSP; Streamer; 2.0 — May support video streaming" in html
    assert "Port 53 (udp): domain — Helps devices look up network addresses" in html
    assert "Port 554 (tcp): Service not identified</li>" in html
    assert "Port 12345 (tcp): custom-service</li>" in html
    assert "An open port does not by itself indicate danger" in html
    assert "port numbers alone do not confirm" in html
