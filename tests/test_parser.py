import pytest

from guardian import NmapParseError, parse_nmap_file, parse_nmap_xml


def test_extracts_hosts_addresses_and_open_services():
    devices = parse_nmap_xml('''<?xml version="1.0"?>
    <!DOCTYPE nmaprun>
    <nmaprun><host><status state="up" reason="arp-response"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example"/>
    <hostnames><hostname name="living-room"/></hostnames>
    <ports><port protocol="tcp" portid="554"><state state="open"/>
    <service name="rtsp" product="Streamer" version="1" extrainfo="example" tunnel="ssl"/>
    </port><port protocol="tcp" portid="80"><state state="closed"/></port>
    <port protocol="udp" portid="53"><state state="open|filtered"/></port>
    </ports></host><host><status state="down"/></host></nmaprun>''')
    device, offline = devices
    assert device.ip_addresses == ("192.0.2.1", "2001:db8::1")
    assert device.mac_addresses == ("AA:BB:CC:DD:EE:FF",)
    assert device.manufacturers == ("Example",)
    assert device.hostnames == ("living-room",)
    assert (device.status, device.status_reason) == ("up", "arp-response")
    assert len(device.open_ports) == 1
    port = device.open_ports[0]
    assert (port.number, port.protocol) == (554, "tcp")
    assert (port.service.name, port.service.product, port.service.version,
            port.service.extra_info, port.service.tunnel) == ("rtsp", "Streamer", "1", "example", "ssl")
    assert offline.status == "down"


def test_missing_optional_information():
    device, = parse_nmap_xml('<nmaprun><host><ports><port portid="80"><state state="open"/></port></ports></host></nmaprun>')
    assert device.status == "unknown"
    assert device.ip_addresses == device.mac_addresses == device.manufacturers == device.hostnames == ()
    assert device.open_ports[0].service is None
    assert parse_nmap_xml("<nmaprun/>") == ()


@pytest.mark.parametrize("xml", ["", "<nmaprun>", "<other/>", "<nmaprun><host></nmaprun>"])
def test_invalid_xml_has_actionable_error(xml):
    with pytest.raises(NmapParseError, match="XML"):
        parse_nmap_xml(xml)


@pytest.mark.parametrize("number", ["", "bad", "-1", "65536"])
def test_invalid_open_port_has_context(number):
    with pytest.raises(NmapParseError, match="Host 1.*invalid open port"):
        parse_nmap_xml(f'<nmaprun><host><ports><port portid="{number}"><state state="open"/></port></ports></host></nmaprun>')


def test_file_reading_and_missing_file(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_bytes(b'<nmaprun><host/></nmaprun>')
    assert len(parse_nmap_file(path)) == 1
    with pytest.raises(NmapParseError, match="Could not open scan file"):
        parse_nmap_file(tmp_path / "missing.xml")


def test_xml_external_entities_are_not_resolved():
    with pytest.raises(NmapParseError):
        parse_nmap_xml('<!DOCTYPE nmaprun [<!ENTITY external SYSTEM "file:///private">]><nmaprun>&external;</nmaprun>')
