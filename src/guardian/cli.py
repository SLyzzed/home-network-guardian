"""Command-line access to the existing scan parser and report writer."""

import argparse
from pathlib import Path
from collections.abc import Sequence

from .parser import NmapParseError, parse_nmap_file
from .report import write_html_report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian")
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report", help="Create an offline HTML report from Nmap XML")
    report.add_argument("input", type=Path, help="Path to an Nmap XML scan")
    report.add_argument("--output", type=Path, required=True, help="HTML output path")
    args = parser.parse_args(argv)

    try:
        devices = parse_nmap_file(args.input)
        output = write_html_report(devices, args.output)
    except (NmapParseError, OSError) as exc:
        parser.exit(1, f"guardian: error: {exc}\n")
    print(f"Report written to {output}")
    return 0
