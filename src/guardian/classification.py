"""Conservative rules describing device evidence, never a threat verdict."""

from dataclasses import dataclass
from enum import Enum

from .models import Device


class Category(str, Enum):
    NETWORKING = "Likely networking equipment"
    STREAMING = "Possible camera or streaming device"
    IDENTIFIED = "Other identified device"
    UNKNOWN = "Unknown device"


@dataclass(frozen=True)
class Classification:
    category: Category
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]
    observations: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.reasons or any(not reason.strip() for reason in self.reasons):
            raise ValueError("Every classification must include a non-empty explanation.")

    @property
    def explanation(self) -> str:
        """Separate what the scan reports from what the rules infer."""
        observations = " ".join(self.observations) or "No scan observations were supplied."
        assumptions = " ".join(self.assumptions or self.reasons)
        return (f"Reported observations: {observations}\n"
                f"Assumptions and interpretation: {assumptions}\n"
                f"Limitations: {' '.join(self.limitations)}")


def classify_device(device: Device) -> Classification:
    """Prefer streaming evidence, then network services, then identity clues.

    Port numbers alone and manufacturer guesses do not establish device type.
    Results describe the supplied scan, which may no longer reflect the device.
    """
    services = {p.service.name.casefold() for p in device.open_ports
                if p.service and p.service.name}
    streaming = services & {"rtsp", "rtsps"}
    networking = services & {"dhcp", "dhcps", "bootps", "domain"}
    observations = tuple(
        f"The scan reports an open {port.protocol} port {port.number}"
        + (f" with service name {port.service.name}." if port.service and port.service.name else ".")
        for port in device.open_ports
    )
    observations += tuple(f"The scan reports a hardware manufacturer: {name}." for name in device.manufacturers)
    observations += tuple(f"The scan reports a device name: {name}." for name in device.hostnames)
    limits = ("These observations confirm what the supplied scan reports, not independently verified device behavior or identity. "
              "Scan clues can be incomplete, incorrect, or outdated; they do not establish whether a device is safe or unsafe.",)
    if streaming:
        assumptions = ("The reported streaming service suggests potential video streaming; the device type is uncertain.",)
        return Classification(Category.STREAMING,
            observations + assumptions,
            limits + ("RTSP does not confirm a camera; other devices can stream video too.",),
            observations, assumptions)
    if networking:
        assumptions = ("Services that help devices find internet addresses or join a network "
                       "suggest this may be networking equipment, such as a router.",)
        return Classification(Category.NETWORKING,
            observations + assumptions,
            limits + ("Computers and other devices can also provide these services.",),
            observations, assumptions)
    reasons = []
    if device.manufacturers:
        reasons.append(f"The scan reports a hardware manufacturer: {', '.join(device.manufacturers)}.")
    if device.hostnames:
        reasons.append(f"The scan reports a device name: {', '.join(device.hostnames)}.")
    if reasons:
        assumptions = ("The reported name or manufacturer provides an identity clue, but the device type remains unconfirmed.",)
        return Classification(Category.IDENTIFIED, observations + assumptions, limits + (
            "A manufacturer or device name is an identity clue, not confirmation of device type. Espressif hardware alone does not indicate a camera.",),
            observations, assumptions)
    assumptions = ("The scan did not provide enough information to identify this device.",)
    return Classification(Category.UNKNOWN,
        observations + assumptions,
        limits + ("Unknown means unidentified. It does not mean suspicious or malicious.",),
        observations, assumptions)
