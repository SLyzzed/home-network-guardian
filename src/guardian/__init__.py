"""Local-first, explainable home network analysis."""

from .classification import Category, Classification, classify_device
from .models import Device, Port, Service
from .parser import NmapParseError, parse_nmap_file, parse_nmap_xml
from .report import generate_html_report, write_html_report

__all__ = [
    "Category", "Classification", "Device", "Port", "Service",
    "NmapParseError", "classify_device", "parse_nmap_file", "parse_nmap_xml",
    "generate_html_report", "write_html_report",
]
