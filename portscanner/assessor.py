"""High-level scan API – orchestrates nmap and converts results to models.

Typical usage::

    from portscanner.assessor import assess

    report = assess("scanme.nmap.org", top_ports=100)
    for host in report.hosts:
        for port in host.open_ports:
            print(host.address, port.port, port.service.describe() if port.service else "")
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
from typing import Callable, Iterable

from portscanner.constants import DEFAULT_TIMEOUT, DEFAULT_TIMING, TARGET_RE
from portscanner.rustscan_utils import run_scan_rustscan
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
        # Reject leading '-': targets are passed to nmap/rustscan as argv, and a
        # token like "-oX" or "--script" would be consumed as a flag rather than
        # a target (argument injection — distinct from shell injection). Neither
        # tool has a universal end-of-options marker, so rejection is the safe path.
        if target.startswith("-") or not TARGET_RE.match(target):
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
    cpe = raw.get("cpe")
    return ServiceInfo(
        name=raw.get("name"),
        product=raw.get("product"),
        version=raw.get("version"),
        extrainfo=raw.get("extrainfo"),
        method=raw.get("method"),
        cpe=list(cpe) if isinstance(cpe, list) else [],
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
    scripts = raw.get("scripts")
    return PortResult(
        port=port_num,
        protocol=raw.get("protocol") or "tcp",
        state=PortState.from_nmap(state_raw.get("state")),
        reason=state_raw.get("reason"),
        service=_to_service(raw.get("service")),
        scripts=list(scripts) if isinstance(scripts, list) else [],
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


def _merge_hosts_by_address(hosts: list[HostResult]) -> list[HostResult]:
    """Coalesce hosts that share an address into one entry.

    When several targets resolve to the same IP (e.g. two DNS names for one
    server), nmap emits a separate ``<host>`` block per target. Those describe
    the same machine, so they are merged: hostnames are unioned (order
    preserved) and ports are unioned by ``(protocol, port)``, preferring an
    open state and a populated service when the same port appears twice.

    Hosts with no address (empty string) are never merged together — each is
    kept as its own entry, since a missing address is not evidence that two
    blocks describe the same machine.

    :param hosts: Parsed host results, possibly with duplicate addresses.
    :returns: One :class:`HostResult` per non-empty address, first-seen order
        preserved; address-less hosts pass through individually.
    :rtype: list[HostResult]
    """
    by_addr: dict[str, HostResult] = {}
    merged: list[HostResult] = []
    for host in hosts:
        existing = by_addr.get(host.address) if host.address else None
        if existing is None:
            if host.address:
                by_addr[host.address] = host
            merged.append(host)
            continue
        for name in host.hostnames:
            if name not in existing.hostnames:
                existing.hostnames.append(name)
        ports_by_key = {(p.protocol, p.port): p for p in existing.ports}
        for port in host.ports:
            key = (port.protocol, port.port)
            current = ports_by_key.get(key)
            if current is None:
                existing.ports.append(port)
                ports_by_key[key] = port
            elif current.state != PortState.OPEN and port.state == PortState.OPEN:
                # Prefer the open observation (and its service detail).
                existing.ports[existing.ports.index(current)] = port
                ports_by_key[key] = port
        if existing.state != HostState.UP and host.state == HostState.UP:
            existing.state = host.state
            existing.reason = host.reason
    for host in merged:
        host.ports.sort(key=lambda p: (p.protocol, p.port))
    return merged


def _address_family(target: str) -> str:
    """Return ``"6"`` for an IPv6 literal/CIDR target, else ``"4"``.

    Hostnames (which nmap resolves, defaulting to IPv4) map to ``"4"``.

    :param target: A host, IP, or CIDR string.
    :returns: ``"4"`` or ``"6"``.
    :rtype: str
    """
    try:
        return "6" if ipaddress.ip_network(target, strict=False).version == 6 else "4"
    except ValueError:
        return "4"


def _family_invocations(
    targets: list[str], base_args: list[str]
) -> list[tuple[list[str], list[str]]]:
    """Split *targets* by address family into one nmap invocation per family.

    IPv4 and IPv6 cannot share a single nmap run; the IPv6 group gets ``-6``.

    :param targets: Validated targets.
    :param base_args: nmap flags shared by every group (from ``build_nmap_args``).
    :returns: List of ``(targets, args)`` invocations, IPv4 first.
    :rtype: list[tuple[list[str], list[str]]]
    """
    groups: dict[str, list[str]] = {}
    for target in targets:
        groups.setdefault(_address_family(target), []).append(target)
    invocations: list[tuple[list[str], list[str]]] = []
    for family in ("4", "6"):
        group = groups.get(family)
        if group:
            invocations.append((group, base_args + (["-6"] if family == "6" else [])))
    return invocations


def _rustscan_invocations(
    open_map: dict[str, list[int]],
    *,
    timing: int,
    host_timeout: float | None,
    max_retries: int | None,
    service_detection: bool,
    scripts: bool,
) -> list[tuple[list[str], list[str]]]:
    """Build per-host-targeted nmap invocations from rustscan's discovery map.

    Hosts are grouped by (address family, exact open-port set) so each nmap run
    scans only the ports actually found open on those hosts — avoiding the old
    global-union over-scan. ``-Pn`` is forced (rustscan already proved liveness).

    :param open_map: Host → open ports, from :func:`run_scan_rustscan`.
    :returns: List of ``(hosts, args)`` invocations.
    :rtype: list[tuple[list[str], list[str]]]
    """
    buckets: dict[tuple[str, tuple[int, ...]], list[str]] = {}
    for host, ports in open_map.items():
        family = "6" if ":" in host else "4"
        buckets.setdefault((family, tuple(ports)), []).append(host)

    invocations: list[tuple[list[str], list[str]]] = []
    for (family, portset), hosts in buckets.items():
        args = build_nmap_args(
            ports=",".join(str(p) for p in portset),
            timing=timing,
            host_timeout=host_timeout,
            max_retries=max_retries,
            skip_ping=True,
            service_detection=service_detection,
            scripts=scripts,
        )
        if family == "6":
            args = args + ["-6"]
        invocations.append((hosts, args))
    return invocations


def _backfill_rustscan_hosts(
    hosts: list[HostResult], open_map: dict[str, list[int]]
) -> list[HostResult]:
    """Add hosts rustscan found but nmap did not report (e.g. nmap timed out).

    rustscan proved these ports open via a completed TCP connect, so if the nmap
    phase is killed (slow ``-sV``/``-sC``) before finishing a host, fall back to
    rustscan's finding rather than dropping the host entirely — the port
    inventory is still accurate, just without nmap's service/script detail.

    :param hosts: Hosts parsed from nmap output (may be empty on timeout).
    :param open_map: rustscan's host → open ports map.
    :returns: *hosts* with any missing rustscan hosts appended.
    :rtype: list[HostResult]
    """
    present = {host.address for host in hosts}
    for address, ports in open_map.items():
        if address not in present:
            hosts.append(
                HostResult(
                    address=address,
                    state=HostState.UP,
                    ports=[
                        PortResult(port=p, protocol="tcp", state=PortState.OPEN)
                        for p in ports
                    ],
                )
            )
    return hosts


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
    scripts: bool = False,
    rustscan: bool = False,
    rustscan_batch: int | None = None,
    rustscan_timeout: int | None = None,
    rustscan_ports: str | None = None,
    rustscan_ulimit: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    progress_cb: Callable[[str], None] | None = None,
) -> ScanReport:
    """Scan one or more *targets* with nmap and return a :class:`~portscanner.models.ScanReport`.

    When *rustscan* is enabled, a fast rustscan sweep discovers open ports first
    and nmap then runs service detection **only** on the union of ports rustscan
    reported open — much faster than nmap sweeping a wide range itself. rustscan
    uses a TCP connect scan, so it needs no root. If rustscan finds no open
    ports, nmap is skipped and a report with no hosts is returned.

    :param targets: A single target string or an iterable of targets — each a
        host, IP, or CIDR range (e.g. ``"scanme.nmap.org"``, ``"10.0.0.0/24"``).
    :param target_file: Optional path to a file listing targets (one or more
        per line; blank lines and ``#`` comments ignored). Targets from the file
        are merged with *targets* and de-duplicated.
    :param ports: Explicit ``-p`` port spec; mutually exclusive with *top_ports*
        and with *rustscan*.
    :param top_ports: Scan nmap's N most common ports (``--top-ports``);
        mutually exclusive with *ports* and with *rustscan*. When neither is
        given (and *rustscan* is off), nmap's default top-1000 ports are scanned.
    :param timing: nmap timing template 0–5 (``-T<n>``); defaults to 4.
    :param host_timeout: Per-host time budget in seconds (``--host-timeout``).
    :param max_retries: Cap on probe retransmissions (``--max-retries``).
    :param skip_ping: Skip host discovery and treat hosts as up (``-Pn``).
    :param service_detection: Enable service/version detection (``-sV``).
    :param scripts: Run nmap's default NSE scripts (``-sC``); results surface on
        each :class:`~portscanner.models.PortResult` as ``scripts``.
    :param rustscan: Run a rustscan fast-discovery phase before nmap.
    :param rustscan_batch: rustscan parallel batch size (``--batch-size``).
    :param rustscan_timeout: rustscan per-port timeout in ms (``--timeout``).
    :param rustscan_ports: Discovery port spec rustscan sweeps (default: its
        full range).
    :param rustscan_ulimit: File-descriptor limit rustscan requests
        (``--ulimit``); raising it speeds up full-range scans.
    :param timeout: Per-process subprocess timeout in seconds. It is applied to
        the rustscan run and the nmap run **independently**, so a two-phase
        ``rustscan`` scan can take up to roughly twice this value in total.
    :param progress_cb: Optional callback invoked with progress strings.
    :returns: Completed scan report (inventory only — no grade/severity).
    :rtype: ScanReport
    :raises ValueError: For missing/invalid targets or scan parameters (e.g.
        combining ``--rustscan`` with ``--ports``/``--top-ports``).
    :raises RuntimeError: If a scanner is unavailable or nmap output cannot be
        parsed.
    """
    target_list = _collect_targets(targets, target_file)

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    prefix = ""
    open_map: dict[str, list[int]] = {}
    if rustscan:
        if ports or top_ports is not None:
            raise ValueError(
                "--ports/--top-ports cannot be combined with --rustscan; "
                "use --rustscan-ports to set the discovery range."
            )
        open_map, rustscan_cmd = run_scan_rustscan(
            target_list,
            ports=rustscan_ports,
            batch=rustscan_batch,
            port_timeout=rustscan_timeout,
            ulimit=rustscan_ulimit,
            timeout=timeout,
            progress_cb=progress_cb,
        )
        if not open_map:
            _cb("rustscan found no open ports.")
            return ScanReport(
                targets=target_list, command=rustscan_cmd, hosts=[], timed_out=False
            )
        total_ports = sum(len(p) for p in open_map.values())
        _cb(f"rustscan found {total_ports} open port(s); running nmap…")
        # Each host is scanned only for the ports rustscan found open on it
        # (grouped by family + port-set), not a global union.
        invocations = _rustscan_invocations(
            open_map,
            timing=timing,
            host_timeout=host_timeout,
            max_retries=max_retries,
            service_detection=service_detection,
            scripts=scripts,
        )
        prefix = f"{rustscan_cmd} && "
    else:
        base_args = build_nmap_args(
            ports=ports,
            top_ports=top_ports,
            timing=timing,
            host_timeout=host_timeout,
            max_retries=max_retries,
            skip_ping=skip_ping,
            service_detection=service_detection,
            scripts=scripts,
        )
        invocations = _family_invocations(target_list, base_args)
        label = (
            target_list[0] if len(target_list) == 1 else f"{len(target_list)} targets"
        )
        _cb(f"Scanning {label}…")

    # IPv4 and IPv6 (and, in rustscan mode, distinct port-sets) run as separate
    # nmap invocations; their results are merged into one report.
    raw_hosts: list[dict] = []
    timed_out = False
    commands: list[str] = []
    for inv_targets, inv_args in invocations:
        commands.append(shlex.join(build_command(inv_targets, inv_args)))
        inv_hosts, inv_timed_out = run_scan(
            inv_targets, args=inv_args, timeout=timeout, progress_cb=progress_cb
        )
        raw_hosts.extend(inv_hosts)
        timed_out = timed_out or inv_timed_out

    command = prefix + " ; ".join(commands)
    hosts = _merge_hosts_by_address([_to_host(h) for h in raw_hosts])
    if rustscan:
        # Salvage rustscan's findings for any host nmap didn't finish (timeout).
        hosts = _backfill_rustscan_hosts(hosts, open_map)
    hosts.sort(key=lambda h: h.address)
    _cb(f"Parsed {len(hosts)} host(s).")

    return ScanReport(
        targets=target_list,
        command=command,
        hosts=hosts,
        timed_out=timed_out,
    )
