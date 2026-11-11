import pytest

from guardian import Category, Classification, Device, Port, Service, classify_device, parse_nmap_xml


@pytest.mark.parametrize("device", [
    Device(),
    Device(manufacturers=("Espressif",)),
    Device(hostnames=("office-pc",)),
    Device(open_ports=(Port(53, "udp", Service("domain")),)),
    Device(open_ports=(Port(554, "tcp", Service("rtsp")),)),
])
def test_every_classification_has_display_ready_explanation(device):
    result = classify_device(device)
    assert result.explanation.strip()
    assert all(reason in result.explanation for reason in result.reasons)
    assert all(limit in result.explanation for limit in result.limitations)
    assert "Reported observations:" in result.explanation
    assert "Assumptions and interpretation:" in result.explanation
    assert result.assumptions
    assert all(text.startswith("The scan reports") for text in result.observations)
    assert "not independently verified" in result.explanation


@pytest.mark.parametrize("reasons", [(), ("",), ("  ",)])
def test_classification_cannot_omit_explanation(reasons):
    with pytest.raises(ValueError, match="non-empty explanation"):
        Classification(Category.UNKNOWN, reasons, ())


@pytest.mark.parametrize("name", ["rtsp", "RTSP", "rtsps"])
def test_streaming_is_evidence_not_camera_confirmation(name):
    result = classify_device(Device(open_ports=(Port(8554, "tcp", Service(name)),)))
    assert result.category == Category.STREAMING
    assert any("potential video streaming" in text for text in result.assumptions)
    assert any("does not confirm a camera" in text for text in result.limitations)


def test_espressif_alone_is_not_a_camera():
    result = classify_device(Device(manufacturers=("Espressif Inc.",)))
    assert result.category == Category.IDENTIFIED
    assert any("alone does not indicate a camera" in text for text in result.limitations)


def test_unknown_is_not_a_threat_verdict():
    result = classify_device(Device())
    assert result.category == Category.UNKNOWN
    assert any("does not mean suspicious or malicious" in text for text in result.limitations)


@pytest.mark.parametrize("service", ["domain", "dhcp", "dhcps", "bootps"])
def test_network_services_are_explained_with_uncertainty(service):
    result = classify_device(Device(open_ports=(Port(53, "udp", Service(service)),)))
    assert result.category == Category.NETWORKING
    assert service in result.reasons[0]
    assert any("other devices" in text for text in result.limitations)


def test_port_number_alone_does_not_classify_camera():
    assert classify_device(Device(open_ports=(Port(554, "tcp"),))).category == Category.UNKNOWN


def test_hostname_is_identity_clue():
    assert classify_device(Device(hostnames=("office-pc",))).category == Category.IDENTIFIED


def test_streaming_takes_precedence_and_closed_service_is_ignored():
    device, = parse_nmap_xml('''<nmaprun><host><ports>
    <port portid="53" protocol="udp"><state state="open"/><service name="domain"/></port>
    <port portid="554" protocol="tcp"><state state="closed"/><service name="rtsp"/></port>
    </ports></host></nmaprun>''')
    assert classify_device(device).category == Category.NETWORKING
    both = Device(open_ports=device.open_ports + (Port(8554, "tcp", Service("rtsp")),))
    assert classify_device(both).category == Category.STREAMING
