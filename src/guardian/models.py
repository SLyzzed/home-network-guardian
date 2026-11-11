"""Immutable observations from a network scan; absent data stays absent."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None


@dataclass(frozen=True)
class Port:
    number: int
    protocol: str
    service: Service | None = None


@dataclass(frozen=True)
class Device:
    ip_addresses: tuple[str, ...] = ()
    mac_addresses: tuple[str, ...] = ()
    manufacturers: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()
    status: str = "unknown"
    status_reason: str | None = None
    open_ports: tuple[Port, ...] = ()
