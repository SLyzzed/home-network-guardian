"""Local Nmap host discovery, invoked only after CLI consent."""
import os
from pathlib import Path
import shutil
import subprocess

from .network import DiscoveryError, Interface, PRIVATE


def find_nmap() -> Path | None:
    executable = shutil.which('nmap.exe') or shutil.which('nmap')
    if executable:
        return Path(executable)
    for variable in ('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432'):
        root = os.environ.get(variable)
        if root:
            candidate = Path(root) / 'Nmap' / 'nmap.exe'
            if candidate.is_file():
                return candidate
    for root in (Path('C:/Program Files'), Path('C:/Program Files (x86)')):
        candidate = root / 'Nmap' / 'nmap.exe'
        if candidate.is_file():
            return candidate
    return None


def build_command(executable: Path, interface: Interface) -> list[str]:
    scope = interface.scope
    if scope.num_addresses > 256 or not any(scope.subnet_of(p) for p in PRIVATE):
        raise DiscoveryError('Refusing a scan outside a private IPv4 network of at most 256 addresses.')
    return [str(executable), '-sn', '-n', '-S', str(interface.address.ip), '-oX', '-', str(scope)]


def run_discovery(executable: Path, interface: Interface) -> str:
    try:
        result = subprocess.run(build_command(executable, interface), capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=120, check=True)
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError('Discovery timed out after 120 seconds. No report was generated.') from exc
    except subprocess.CalledProcessError as exc:
        raise DiscoveryError('Nmap discovery failed. Check Nmap/Npcap installation and network permissions. '
                             + (exc.stderr or '').strip()[:500]) from exc
    except OSError as exc:
        raise DiscoveryError('Could not start Nmap. Check its installation and try again.') from exc
    if not result.stdout.strip():
        raise DiscoveryError('Nmap returned no XML results.')
    return result.stdout
