"""Command-line access to the existing scan parser and report writer."""

import argparse
from pathlib import Path
from collections.abc import Sequence

from .parser import NmapParseError, parse_nmap_file, parse_nmap_xml
from .report import write_html_report
from .network import DiscoveryError, detect_interfaces, select_interface
from .discovery import find_nmap, build_command, run_discovery
import subprocess


def scan_network(dry_run: bool):
    interface = select_interface(detect_interfaces())
    print(f'Interface: {interface.name}; IPv4/subnet: {interface.address}')
    print(f'Proposed scope: {interface.scope} ({interface.scope.num_addresses} addresses maximum).')
    if interface.address.network != interface.scope:
        print('Your subnet is larger; only the /24 containing your address will be checked.')
    print('Host discovery only. Scan only networks you own or have permission to scan.')
    print('Guardian does not upload results. Synced folders such as OneDrive can copy reports to cloud storage.')
    print('No camera feeds, credentials, exploits, or background scanning.')
    executable = find_nmap()
    if dry_run:
        print('Dry run; no scan will run. Intended command:')
        print(subprocess.list2cmdline(build_command(executable or Path('nmap.exe'), interface)))
        if executable is None:
            print('Nmap is not installed or could not be found.')
        return None
    if executable is None:
        raise DiscoveryError('Nmap was not found. Download the Windows installer from https://nmap.org/download.html, '
                             'install Nmap with its Npcap option, then reopen your terminal. Nothing was installed automatically.')
    try:
        consent = input('Do you have permission and want to scan this scope? Type yes to continue: ')
    except EOFError:
        consent = ''
    if consent.strip().casefold() != 'yes':
        print('Cancelled; nothing was scanned.')
        return None
    # Recheck before starting: adapter state may have changed during the prompt.
    if interface not in detect_interfaces():
        raise DiscoveryError('Network settings changed. Run the command again to review a new scope.')
    return parse_nmap_xml(run_discovery(executable, interface))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian")
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report", help="Create an offline HTML report from Nmap XML")
    report.add_argument("input", type=Path, help="Path to an Nmap XML scan")
    report.add_argument("--output", type=Path, required=True, help="HTML output path")
    scan = commands.add_parser('scan', help='Discover devices on a private Windows network with consent')
    scan.add_argument('--output', type=Path, required=True, help='HTML output path')
    scan.add_argument('--dry-run', action='store_true', help='Show the scope and command without scanning')
    args = parser.parse_args(argv)

    try:
        devices = scan_network(args.dry_run) if args.command == 'scan' else parse_nmap_file(args.input)
        if devices is None:
            return 0
        output = write_html_report(devices, args.output)
    except (NmapParseError, OSError, DiscoveryError) as exc:
        parser.exit(1, f"guardian: error: {exc}\n")
    except KeyboardInterrupt:
        parser.exit(130, '\nguardian: cancelled.\n')
    print(f"Report written to {output.resolve()}")
    return 0
