"""Shared result dataclasses and enums for portscanner.

The scanner shells out to ``nmap -oX -`` and hands the XML to the
`nmap2json <https://github.com/D4-project/nmap2json>`_ library, which returns
one dict per host. Those dicts are converted into the typed objects defined
here. :class:`ScanReport` is the top-level aggregate returned by
:func:`portscanner.assessor.assess`.

This module is *inventory only*: it records open ports and detected services.
It assigns no letter grade and no severity — per the platform convention,
grading is reserved for ``mailvalidator`` and ``headersvalidator``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HostState(str, Enum):
    """Liveness state of a scanned host, as reported by nmap.

    - ``UP``      – host responded / was assumed up (``-Pn``).
    - ``DOWN``    – host did not respond to host discovery.
    - ``UNKNOWN`` – nmap emitted no status for the host.
    """

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(str, Enum):
    """State of a single port, mirroring nmap's port-state vocabulary.

    - ``OPEN``            – an application is accepting connections.
    - ``CLOSED``          – reachable but no application is listening.
    - ``FILTERED``        – a packet filter prevents state determination.
    - ``OPEN_FILTERED``   – nmap cannot tell whether open or filtered.
    - ``CLOSED_FILTERED`` – nmap cannot tell whether closed or filtered.
    - ``UNFILTERED``      – reachable but nmap cannot tell open vs closed.
    - ``UNKNOWN``         – state string not recognised.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNFILTERED = "unfiltered"
    UNKNOWN = "unknown"

    @classmethod
    def from_nmap(cls, value: str | None) -> "PortState":
        """Map an nmap port-state string to a :class:`PortState`.

        :param value: The raw ``state`` attribute from nmap (e.g. ``"open"``).
        :returns: The matching member, or :data:`PortState.UNKNOWN`.
        :rtype: PortState
        """
        try:
            return cls(value) if value is not None else cls.UNKNOWN
        except ValueError:
            return cls.UNKNOWN


@dataclass
class ServiceInfo:
    """Service/version metadata for a port, from nmap's ``-sV`` detection.

    :param name: Nmap's service name guess (e.g. ``"http"``, ``"ssh"``).
    :param product: Detected product/application (e.g. ``"OpenSSH"``).
    :param version: Detected version string (e.g. ``"9.6p1"``).
    :param extrainfo: Free-form extra info nmap attached (e.g. ``"Ubuntu"``).
    :param method: How the service was determined (``"table"`` or ``"probed"``).
    :param cpe: CPE identifiers nmap emitted for the service (from ``<cpe>``
        child elements), or an empty list.
    """

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    method: str | None = None
    cpe: list[str] = field(default_factory=list)

    def describe(self) -> str:
        """Return a compact one-line human description of the service.

        :returns: ``"OpenSSH 9.6p1 (Ubuntu)"``-style string, or ``""`` if empty.
        :rtype: str
        """
        parts = [p for p in (self.product, self.version) if p]
        text = " ".join(parts)
        if self.extrainfo:
            text = f"{text} ({self.extrainfo})" if text else self.extrainfo
        return text


@dataclass
class PortResult:
    """A single scanned port and its detected service.

    :param port: Port number (e.g. ``443``).
    :param protocol: Transport protocol (``"tcp"`` or ``"udp"``).
    :param state: Port state (open/closed/filtered/…).
    :param reason: Why nmap assigned that state (e.g. ``"syn-ack"``).
    :param service: Detected service metadata, or ``None`` when unavailable.
    :param scripts: NSE script results for this port (from ``-sC``/``--scripts``),
        each a dict with at least ``id`` and ``output`` keys; empty when no
        scripts ran.
    :param hsh256: Stable per-port SHA-256 hash from nmap2json (diff-friendly).
    """

    port: int
    protocol: str
    state: PortState = PortState.UNKNOWN
    reason: str | None = None
    service: ServiceInfo | None = None
    scripts: list[dict] = field(default_factory=list)
    hsh256: str | None = None


@dataclass
class HostResult:
    """A single scanned host with its port inventory.

    :param address: The host's address (IPv4/IPv6) as reported by nmap.
    :param hostnames: Reverse/forward hostnames nmap associated with the host.
    :param state: Host liveness state.
    :param reason: Why nmap assigned the host state (e.g. ``"echo-reply"``).
    :param ports: Per-port results (only ports nmap reported are included).
    :param hsh256: Stable per-host SHA-256 hash from nmap2json (diff-friendly).
    """

    address: str
    hostnames: list[str] = field(default_factory=list)
    state: HostState = HostState.UNKNOWN
    reason: str | None = None
    ports: list[PortResult] = field(default_factory=list)
    hsh256: str | None = None

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only the ports in the :data:`PortState.OPEN` state.

        :returns: Open :class:`PortResult` objects, preserving order.
        :rtype: list[PortResult]
        """
        return [p for p in self.ports if p.state == PortState.OPEN]


@dataclass
class ScanReport:
    """Aggregated scan result returned by :func:`portscanner.assessor.assess`.

    :param targets: The targets that were scanned (hosts, IPs, or CIDR ranges).
        A single scan may cover many targets — passed on the command line and/or
        read from a file — all handed to one nmap invocation.
    :param command: The exact nmap command line that was executed.
    :param hosts: Per-host results parsed from the nmap output.
    :param timed_out: ``True`` when the nmap process was killed on timeout.
    """

    targets: list[str] = field(default_factory=list)
    command: str = ""
    hosts: list[HostResult] = field(default_factory=list)
    timed_out: bool = False

    @property
    def target(self) -> str:
        """Return the targets as a single space-joined expression.

        Kept for convenient display and backward compatibility with callers
        that expect a single scalar target string.

        :returns: Space-joined target list (e.g. ``"host1 10.0.0.0/24"``).
        :rtype: str
        """
        return " ".join(self.targets)
