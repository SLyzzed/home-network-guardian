"""Conservative Windows IPv4 discovery. No network probes are sent here."""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
import json
import subprocess
import sys


class DiscoveryError(ValueError):
    """Discovery cannot safely continue."""


PRIVATE = tuple(IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
SUSPECT = ("vpn", "virtual", "hyper-v", "vmware", "vethernet", "wireguard", "tunnel", "tap", "tun", "tailscale", "zerotier", "loopback", "wsl", "docker", "ppp")


@dataclass(frozen=True)
class Interface:
    index: int
    name: str
    address: IPv4Interface
    automatic: bool

    @property
    def scope(self) -> IPv4Network:
        # Keep the selected address's /24 on large networks, never expand small ones.
        return IPv4Network((self.address.ip, max(24, self.address.network.prefixlen)), strict=False)


# Fixed script, never interpolated with user input. HardwareInterface distinguishes
# physical adapters; unknown/nonphysical adapters always require explicit selection.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rows = @(Get-NetAdapter -IncludeHidden | Where-Object Status -eq 'Up' | ForEach-Object {
    $adapter = $_
    Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource } |
    ForEach-Object {
        [pscustomobject]@{Index=$adapter.ifIndex; Name=$adapter.Name;
        Description=$adapter.InterfaceDescription; Hardware=$adapter.HardwareInterface;
        IP=$_.IPAddress; Prefix=$_.PrefixLength; Status='Up'}
    }
})
ConvertTo-Json -InputObject $rows -Compress
"""


def parse_interfaces(data: str) -> tuple[Interface, ...]:
    try:
        rows = json.loads(data)
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise DiscoveryError("Windows returned invalid network settings.") from exc
    found = []
    for row in rows:
        try:
            if row['Status'] != 'Up':
                continue
            index = int(row['Index'])
            address = IPv4Interface(f"{row['IP']}/{row['Prefix']}")
            network = address.network
            if index <= 0 or not any(network.subnet_of(p) for p in PRIVATE):
                continue
            if network.prefixlen < 31 and address.ip in (network.network_address, network.broadcast_address):
                continue
            name = str(row['Name'])
            label = (name + ' ' + str(row.get('Description', ''))).casefold()
            automatic = row.get('Hardware') is True and not any(s in label for s in SUSPECT)
            item = Interface(index, name, address, automatic)
            if item not in found:
                found.append(item)
        except (KeyError, ValueError, TypeError):
            continue
    return tuple(found)


def detect_interfaces() -> tuple[Interface, ...]:
    if sys.platform != 'win32':
        raise DiscoveryError("Automatic network detection requires Windows.")
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', SCRIPT],
                                capture_output=True, text=True, encoding='utf-8', timeout=20, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError("Could not read Windows network settings. Check your connection and try again.") from exc
    return parse_interfaces(result.stdout)


def select_interface(interfaces: tuple[Interface, ...]) -> Interface:
    if not interfaces:
        raise DiscoveryError("No connected private IPv4 network found. Connect to your home Wi-Fi or Ethernet.")
    # Even a physical adapter alongside a VPN needs an explicit choice.
    if len(interfaces) == 1 and interfaces[0].automatic:
        return interfaces[0]
    print('Choose your home network interface (VPN/virtual adapters are never selected automatically):')
    for number, item in enumerate(interfaces, 1):
        caution = '' if item.automatic else ' [VPN/virtual or unverified adapter]'
        print(f'{number}. {item.name}: {item.address}{caution}')
    try:
        choice = input('Interface number (Enter to cancel): ').strip()
        number = int(choice)
        if not 1 <= number <= len(interfaces):
            raise ValueError
        return interfaces[number - 1]
    except (ValueError, EOFError) as exc:
        raise DiscoveryError('No valid interface selected; nothing was scanned.') from exc
