"""masscan subprocess boundary for the fast port-discovery phase.

This is the second I/O boundary of the package (alongside
:mod:`portscanner.nmap_utils`). It resolves hostnames to IP addresses (masscan
scans IPs/CIDRs, not names), runs masscan to discover open ports quickly, and
parses masscan's ``-oL`` list output. Tests mock :func:`run_scan_masscan`
(subprocess) and :func:`socket.getaddrinfo` (resolution).

masscan needs raw-socket privileges (root or ``CAP_NET_RAW``). A non-zero exit
is raised as :class:`RuntimeError` rather than being treated as "no open ports",
so a privilege failure never masquerades as a clean empty result.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
from typing import Callable

from portscanner.constants import DEFAULT_MASSCAN_PORTS, DEFAULT_MASSCAN_RATE

logger = logging.getLogger("portscanner")


def build_masscan_args(*, ports: str, rate: int) -> list[str]:
    """Build masscan flags (excluding the binary, targets, and ``-oL``).

    :param ports: Port spec masscan scans for discovery (e.g. ``"1-65535"``).
    :param rate: Transmit rate in packets per second (``--rate``).
    :returns: Ordered list of masscan arguments.
    :rtype: list[str]
    """
    return ["-p", ports, "--rate", str(rate)]


def _is_ip_or_cidr(target: str) -> bool:
    """Return ``True`` if *target* is a bare IP address or CIDR network."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def resolve_targets(targets: list[str]) -> list[str]:
    """Resolve hostname targets to IPv4 addresses; pass IPs/CIDRs through.

    masscan cannot scan hostnames, so each non-IP target is resolved via DNS.
    Order is preserved and duplicates removed. Targets that fail to resolve are
    skipped (masscan would reject them anyway).

    :param targets: Targets (hostnames, IPs, or CIDR ranges).
    :returns: Ordered, de-duplicated list of IPs/CIDRs suitable for masscan.
    :rtype: list[str]
    """
    resolved: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if _is_ip_or_cidr(target):
            candidates = [target]
        else:
            try:
                infos = socket.getaddrinfo(target, None, family=socket.AF_INET)
            except OSError:
                infos = []
            candidates = list(dict.fromkeys(info[4][0] for info in infos))
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                resolved.append(candidate)
    return resolved


def parse_masscan_list(text: str) -> list[int]:
    """Parse masscan ``-oL`` output into a sorted list of open TCP ports.

    The list format emits one line per finding::

        open tcp 22 45.33.32.156 1783584930

    Comment lines (``#masscan`` / ``# end``) and malformed lines are ignored.

    :param text: Contents of a masscan ``-oL`` output file.
    :returns: Sorted, de-duplicated open port numbers (union across all hosts).
    :rtype: list[int]
    """
    ports: set[int] = set()
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            try:
                ports.add(int(parts[2]))
            except ValueError:
                continue
    return sorted(ports)


def _read_if_exists(path: str) -> str:
    """Return the contents of *path*, or ``""`` if it does not exist."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def run_scan_masscan(
    targets: list[str],
    *,
    ports: str = DEFAULT_MASSCAN_PORTS,
    rate: int = DEFAULT_MASSCAN_RATE,
    timeout: float,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[list[int], str]:
    """Discover open ports on *targets* with masscan.

    :param targets: Targets (hostnames, IPs, or CIDR ranges); hostnames are
        resolved to IPs first.
    :param ports: Port spec masscan scans (default full range ``1-65535``).
    :param rate: Transmit rate in packets per second.
    :param timeout: Maximum seconds to wait for the masscan process. On timeout,
        masscan is killed and whatever it had written is parsed best-effort.
    :param progress_cb: Optional callback for a progress message before launch.
    :returns: Tuple of (sorted open TCP ports, a reproducible command string).
    :rtype: tuple[list[int], str]
    :raises RuntimeError: If no target resolves, masscan is not installed, or
        masscan exits non-zero (e.g. missing root/``CAP_NET_RAW``).
    """
    ips = resolve_targets(targets)
    if not ips:
        raise RuntimeError("could not resolve any target to an IP address for masscan")

    args = build_masscan_args(ports=ports, rate=rate)
    # Display command uses "-oL -" so the report shows a clean, reproducible
    # invocation rather than the internal temp path.
    command = shlex.join(["masscan", *ips, *args, "-oL", "-"])

    if progress_cb is not None:
        label = ips[0] if len(ips) == 1 else f"{len(ips)} hosts"
        progress_cb(f"Discovering open ports with masscan on {label}…")

    tmpdir = tempfile.mkdtemp(prefix="portscanner-masscan-")
    out_path = os.path.join(tmpdir, "masscan.lst")
    cmd = ["masscan", *ips, *args, "-oL", out_path]
    logger.debug("Executing: %s", " ".join(cmd))

    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise RuntimeError(
                "'masscan' not found – is it installed and on your PATH?"
            )
        except subprocess.TimeoutExpired:
            return parse_masscan_list(_read_if_exists(out_path)), command

        if proc.returncode != 0:
            detail = (proc.stderr or "").strip() or f"masscan exited with code {proc.returncode}"
            raise RuntimeError(f"masscan failed: {detail}")

        return parse_masscan_list(_read_if_exists(out_path)), command
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
