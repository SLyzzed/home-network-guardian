"""Read Nmap -oX output locally without running scans or contacting services."""

from pathlib import Path
import xml.etree.ElementTree as ET

from .models import Device, Port, Service


class NmapParseError(ValueError):
    """The input cannot be interpreted as an Nmap XML scan."""


def _values(elements: list[ET.Element], attribute: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(
        value for element in elements
        if (value := element.get(attribute, "").strip())
    ))


def parse_nmap_xml(xml: str | bytes) -> tuple[Device, ...]:
    """Parse a complete XML document, preserving all hosts and only open ports.

    Missing optional fields use empty tuples or None. Invalid open-port records
    raise an error instead of silently hiding incomplete scan observations.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NmapParseError(f"Could not read the scan XML: {exc}. Export it again using Nmap -oX.") from exc
    if root.tag != "nmaprun":
        raise NmapParseError("Expected an Nmap XML scan with an <nmaprun> root. Export using Nmap -oX.")

    devices = []
    for index, host in enumerate(root.findall("host"), start=1):
        addresses = host.findall("address")
        ips = [a for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}]
        macs = [a for a in addresses if a.get("addrtype") == "mac"]
        status = host.find("status")
        ports = []
        for element in host.findall("ports/port"):
            state = element.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                number = int(element.get("portid", ""))
                if not 0 <= number <= 65535:
                    raise ValueError
            except ValueError as exc:
                raise NmapParseError(f"Host {index} has an invalid open port number: {element.get('portid')!r}.") from exc
            service_element = element.find("service")
            service = None
            if service_element is not None:
                service = Service(*(service_element.get(key) or None for key in
                                    ("name", "product", "version", "extrainfo", "tunnel")))
            ports.append(Port(number, element.get("protocol") or "unknown", service))
        devices.append(Device(
            ip_addresses=_values(ips, "addr"),
            mac_addresses=_values(macs, "addr"),
            manufacturers=_values(macs, "vendor"),
            hostnames=_values(host.findall("hostnames/hostname"), "name"),
            status=(status.get("state") or "unknown") if status is not None else "unknown",
            status_reason=status.get("reason") if status is not None else None,
            open_ports=tuple(ports),
        ))
    return tuple(devices)


def parse_nmap_file(path: str | Path) -> tuple[Device, ...]:
    """Read a scan file as bytes so its XML encoding declaration is respected."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise NmapParseError(f"Could not open scan file {str(path)!r}: {exc.strerror or exc}.") from exc
    return parse_nmap_xml(data)
