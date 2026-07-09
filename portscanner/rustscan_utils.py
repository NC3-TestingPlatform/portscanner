"""rustscan subprocess boundary for the fast port-discovery phase.

This is the second I/O boundary of the package (alongside
:mod:`portscanner.nmap_utils`). It runs `rustscan <https://github.com/RustScan/RustScan>`_
in *greppable* mode (``-g``) to discover open ports quickly across the full
port range, then hands those ports to the nmap phase for service detection.
Tests mock :func:`run_scan_rustscan` (subprocess).

Unlike masscan, rustscan uses a TCP connect scan, so it needs **no root
privileges** and resolves hostnames itself — targets are passed through
unchanged. rustscan's greppable output is one line per host::

    45.33.32.156 -> [22,80]
"""

from __future__ import annotations

import logging
import re
import shlex
import subprocess
from typing import Callable

logger = logging.getLogger("portscanner")

_GREPPABLE_RE = re.compile(r"^\s*(\S.*?)\s*->\s*\[([0-9,\s]*)\]", re.MULTILINE)


def build_rustscan_args(
    *,
    ports: str | None = None,
    batch: int | None = None,
    port_timeout: int | None = None,
    ulimit: int | None = None,
) -> list[str]:
    """Build rustscan flags (excluding the binary and ``-a <targets>``).

    Always requests greppable output (``-g``) so rustscan prints open ports and
    does **not** launch its own nmap — portscanner runs nmap itself afterwards.

    :param ports: Discovery port spec. A ``start-end`` range is passed via
        ``--range``; a comma list (or single port) via ``--ports``. When
        ``None``, rustscan scans its default full range.
    :param batch: Parallel batch size (``--batch-size``).
    :param port_timeout: Per-port timeout in milliseconds (``--timeout``).
    :param ulimit: Open-file-descriptor limit rustscan should request
        (``--ulimit``); raising it speeds up full-range scans.
    :returns: Ordered list of rustscan arguments.
    :rtype: list[str]
    """
    args = ["--greppable"]
    if ports:
        if "-" in ports and "," not in ports:
            args += ["--range", ports]
        else:
            args += ["--ports", ports]
    if batch is not None:
        args += ["--batch-size", str(batch)]
    if port_timeout is not None:
        args += ["--timeout", str(port_timeout)]
    if ulimit is not None:
        args += ["--ulimit", str(ulimit)]
    return args


def parse_rustscan_greppable(text: str) -> dict[str, list[int]]:
    """Parse rustscan greppable output into a per-host open-port map.

    Each finding looks like ``45.33.32.156 -> [22,80]`` (IPv6 hosts may be
    bracketed). Ports are collected per host so the nmap phase can scan each
    host for only its own ports; non-numeric or empty entries are ignored.

    :param text: rustscan stdout in greppable (``-g``) mode.
    :returns: Mapping of host → sorted, de-duplicated open port numbers.
    :rtype: dict[str, list[int]]
    """
    hosts: dict[str, set[int]] = {}
    for match in _GREPPABLE_RE.finditer(text or ""):
        host = match.group(1).strip().strip("[]")
        ports = {int(t) for t in match.group(2).split(",") if t.strip().isdigit()}
        if ports:
            hosts.setdefault(host, set()).update(ports)
    return {host: sorted(ports) for host, ports in hosts.items()}


def run_scan_rustscan(
    targets: list[str],
    *,
    ports: str | None = None,
    batch: int | None = None,
    port_timeout: int | None = None,
    ulimit: int | None = None,
    timeout: float,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[dict[str, list[int]], str]:
    """Discover open ports on *targets* with rustscan (greppable mode).

    :param targets: Targets (hostnames, IPs, or CIDR ranges); rustscan resolves
        hostnames itself, so they are passed through unchanged.
    :param ports: Discovery port spec (default: rustscan's full range).
    :param batch: Parallel batch size (``--batch-size``).
    :param port_timeout: Per-port timeout in milliseconds (``--timeout``).
    :param ulimit: File-descriptor limit rustscan should request (``--ulimit``).
    :param timeout: Maximum seconds to wait for the rustscan process. On
        timeout, rustscan is killed and its partial output is parsed.
    :param progress_cb: Optional callback for a progress message before launch.
    :returns: Tuple of (host → sorted open ports map, the rustscan command string).
    :rtype: tuple[dict[str, list[int]], str]
    :raises RuntimeError: If rustscan is not installed, or exits non-zero with
        an error message and no discovered ports.
    """
    cmd = ["rustscan", "-a", ",".join(targets), *build_rustscan_args(
        ports=ports, batch=batch, port_timeout=port_timeout, ulimit=ulimit
    )]
    command = shlex.join(cmd)
    if progress_cb is not None:
        label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
        progress_cb(f"Discovering open ports with rustscan on {label}…")
    logger.debug("Executing: %s", command)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("'rustscan' not found – is it installed and on your PATH?")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):  # pragma: no cover – text=True yields str
            partial = partial.decode("utf-8", errors="replace")
        return parse_rustscan_greppable(partial), command

    open_ports = parse_rustscan_greppable(proc.stdout)
    if not open_ports and proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        if detail:
            raise RuntimeError(f"rustscan failed: {detail}")
    return open_ports, command
