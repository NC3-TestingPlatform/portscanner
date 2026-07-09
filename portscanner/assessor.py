"""High-level scan API – orchestrates nmap and converts results to models.

Typical usage::

    from portscanner.assessor import assess

    report = assess("scanme.nmap.org", top_ports=100)
    for host in report.hosts:
        for port in host.open_ports:
            print(host.address, port.port, port.service.describe() if port.service else "")
"""

from __future__ import annotations

import logging
import shlex
from typing import Callable, Iterable

from portscanner.constants import DEFAULT_TIMEOUT, DEFAULT_TIMING, TARGET_RE
from portscanner.models import (
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
)
from portscanner.nmap_utils import (
    build_command,
    build_nmap_args,
    read_targets_file,
    run_scan,
)

logger = logging.getLogger("portscanner")


def _collect_targets(
    targets: str | Iterable[str] | None,
    target_file: str | None,
) -> list[str]:
    """Merge, validate, and de-duplicate targets from args and/or a file.

    :param targets: A single target string, an iterable of target strings, or
        ``None``.
    :param target_file: Optional path to a file of targets (see
        :func:`portscanner.nmap_utils.read_targets_file`).
    :returns: Ordered, de-duplicated list of validated targets.
    :rtype: list[str]
    :raises ValueError: If a target is malformed, the file cannot be read, or
        no targets remain after merging.
    """
    if targets is None:
        collected: list[str] = []
    elif isinstance(targets, str):
        collected = [targets]
    else:
        collected = [str(t) for t in targets]

    if target_file:
        collected.extend(read_targets_file(target_file))

    seen: set[str] = set()
    final: list[str] = []
    for raw in collected:
        target = raw.strip()
        if not target:
            continue
        if not TARGET_RE.match(target):
            raise ValueError(f"Invalid target: {target!r}")
        if target not in seen:
            seen.add(target)
            final.append(target)

    if not final:
        raise ValueError(
            "At least one target (or a non-empty --target-file) is required."
        )
    return final


def _to_host_state(value: str | None) -> HostState:
    """Map nmap's host ``state`` string to a :class:`HostState`."""
    try:
        return HostState(value) if value else HostState.UNKNOWN
    except ValueError:
        return HostState.UNKNOWN


def _to_service(raw: dict | None) -> ServiceInfo | None:
    """Build a :class:`ServiceInfo` from an nmap2json ``service`` dict.

    :param raw: The ``service`` sub-dict of a port, or ``None``.
    :returns: A populated :class:`ServiceInfo`, or ``None`` when absent.
    :rtype: ServiceInfo | None
    """
    if not raw:
        return None
    return ServiceInfo(
        name=raw.get("name"),
        product=raw.get("product"),
        version=raw.get("version"),
        extrainfo=raw.get("extrainfo"),
        method=raw.get("method"),
    )


def _to_port(raw: dict) -> PortResult:
    """Convert a single nmap2json port dict into a :class:`PortResult`.

    :param raw: One entry of a host's ``ports`` list.
    :returns: The typed port result.
    :rtype: PortResult
    """
    portid = raw.get("portid")
    try:
        port_num = int(portid)
    except (TypeError, ValueError):
        port_num = 0
    state_raw = raw.get("state") or {}
    return PortResult(
        port=port_num,
        protocol=raw.get("protocol") or "tcp",
        state=PortState.from_nmap(state_raw.get("state")),
        reason=state_raw.get("reason"),
        service=_to_service(raw.get("service")),
        hsh256=raw.get("hsh256"),
    )


def _to_host(raw: dict) -> HostResult:
    """Convert a single nmap2json host dict into a :class:`HostResult`.

    :param raw: One host object from :func:`portscanner.nmap_utils.run_scan`.
    :returns: The typed host result, with ports sorted by protocol then number.
    :rtype: HostResult
    """
    status = raw.get("status") or {}
    hostnames = [
        h.get("name")
        for h in (raw.get("hostnames") or [])
        if isinstance(h, dict) and h.get("name")
    ]
    ports = [_to_port(p) for p in (raw.get("ports") or [])]
    ports.sort(key=lambda p: (p.protocol, p.port))
    return HostResult(
        address=raw.get("addr") or "",
        hostnames=hostnames,
        state=_to_host_state(status.get("state")),
        reason=status.get("reason"),
        ports=ports,
        hsh256=raw.get("hsh256"),
    )


def assess(
    targets: str | Iterable[str],
    *,
    target_file: str | None = None,
    ports: str | None = None,
    top_ports: int | None = None,
    timing: int = DEFAULT_TIMING,
    host_timeout: float | None = None,
    max_retries: int | None = None,
    skip_ping: bool = False,
    service_detection: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    progress_cb: Callable[[str], None] | None = None,
) -> ScanReport:
    """Scan one or more *targets* with nmap and return a :class:`~portscanner.models.ScanReport`.

    :param targets: A single target string or an iterable of targets — each a
        host, IP, or CIDR range (e.g. ``"scanme.nmap.org"``, ``"10.0.0.0/24"``).
    :param target_file: Optional path to a file listing targets (one or more
        per line; blank lines and ``#`` comments ignored). Targets from the file
        are merged with *targets* and de-duplicated.
    :param ports: Explicit ``-p`` port spec; mutually exclusive with *top_ports*.
    :param top_ports: Scan nmap's N most common ports (``--top-ports``);
        mutually exclusive with *ports*. When neither is given, nmap's default
        top-1000 ports are scanned.
    :param timing: nmap timing template 0–5 (``-T<n>``); defaults to 4.
    :param host_timeout: Per-host time budget in seconds (``--host-timeout``).
    :param max_retries: Cap on probe retransmissions (``--max-retries``).
    :param skip_ping: Skip host discovery and treat hosts as up (``-Pn``).
    :param service_detection: Enable service/version detection (``-sV``).
    :param timeout: Overall subprocess timeout in seconds for the nmap run.
    :param progress_cb: Optional callback invoked with progress strings.
    :returns: Completed scan report (inventory only — no grade/severity).
    :rtype: ScanReport
    :raises ValueError: For missing/invalid targets or scan parameters.
    :raises RuntimeError: If nmap is unavailable or its output cannot be parsed.
    """
    target_list = _collect_targets(targets, target_file)

    args = build_nmap_args(
        ports=ports,
        top_ports=top_ports,
        timing=timing,
        host_timeout=host_timeout,
        max_retries=max_retries,
        skip_ping=skip_ping,
        service_detection=service_detection,
    )
    command = shlex.join(build_command(target_list, args))

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    label = target_list[0] if len(target_list) == 1 else f"{len(target_list)} targets"
    _cb(f"Scanning {label}…")
    raw_hosts, timed_out = run_scan(
        target_list, args=args, timeout=timeout, progress_cb=progress_cb
    )

    hosts = [_to_host(h) for h in raw_hosts]
    hosts.sort(key=lambda h: h.address)
    _cb(f"Parsed {len(hosts)} host(s).")

    return ScanReport(
        targets=target_list,
        command=command,
        hosts=hosts,
        timed_out=timed_out,
    )
