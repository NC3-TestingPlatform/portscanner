"""nmap subprocess boundary and nmap2json parsing for portscanner.

This module is the *sole I/O boundary* of the package: every subprocess call
and every dependency on the external ``nmap`` binary lives here, so tests mock
at exactly one place (:func:`run_scan`). Pure command-building
(:func:`build_nmap_args`) and XML parsing (:func:`parse_nmap_xml`) are kept
separate so they can be unit-tested without touching the network.

The scan pipeline is::

    nmap -oX - <target>   →   XML on stdout   →   nmap2json   →   list[dict]
"""

from __future__ import annotations

import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Callable

import defusedxml.ElementTree as DET
from defusedxml.common import DefusedXmlException
from nmap2json.nmap2json import nmap_to_json

from portscanner.constants import DEFAULT_TIMING, MAX_TIMING, MIN_TIMING

logger = logging.getLogger("portscanner")


def build_nmap_args(
    *,
    ports: str | None = None,
    top_ports: int | None = None,
    timing: int = DEFAULT_TIMING,
    host_timeout: float | None = None,
    max_retries: int | None = None,
    skip_ping: bool = False,
    service_detection: bool = True,
    scripts: bool = False,
) -> list[str]:
    """Build the nmap flag list (excluding the binary, ``-oX -``, and target).

    The base profile is always a TCP connect scan (``-sT``) so the module runs
    without root. Flags are emitted in a stable order for reproducible command
    strings.

    :param ports: Explicit port spec passed to ``-p`` (e.g. ``"22,80,443"`` or
        ``"1-1024"``). Mutually exclusive with *top_ports*.
    :param top_ports: Scan nmap's N most common ports via ``--top-ports``.
        Mutually exclusive with *ports*.
    :param timing: nmap timing template 0–5, emitted as ``-T<n>``.
    :param host_timeout: Give up on a host after this many seconds
        (``--host-timeout <n>s``); ``None`` leaves nmap's default.
    :param max_retries: Cap probe retransmissions (``--max-retries``);
        ``None`` leaves nmap's default.
    :param skip_ping: When ``True``, add ``-Pn`` to skip host discovery and
        treat every host as online.
    :param service_detection: When ``True`` (default), add ``-sV`` for
        service/version detection.
    :param scripts: When ``True``, add ``-sC`` to run nmap's default NSE
        scripts (banner grabs, ``ssl-cert``, ``http-title``, …).
    :returns: Ordered list of nmap arguments.
    :rtype: list[str]
    :raises ValueError: If *timing* is out of range, or both *ports* and
        *top_ports* are supplied.
    """
    if not (MIN_TIMING <= timing <= MAX_TIMING):
        raise ValueError(
            f"timing must be between {MIN_TIMING} and {MAX_TIMING}, got {timing}"
        )
    if ports and top_ports:
        raise ValueError("Specify either ports or top_ports, not both.")

    args: list[str] = ["-sT"]
    if service_detection:
        args.append("-sV")
    if scripts:
        args.append("-sC")
    if skip_ping:
        args.append("-Pn")
    if ports:
        args += ["-p", ports]
    elif top_ports is not None:
        args += ["--top-ports", str(top_ports)]
    args.append(f"-T{timing}")
    if host_timeout is not None:
        args += ["--host-timeout", f"{host_timeout:g}s"]
    if max_retries is not None:
        args += ["--max-retries", str(max_retries)]
    return args


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse nmap XML into nmap2json's list-of-host-dicts structure.

    :param xml_text: Raw nmap XML (as produced by ``nmap -oX -``).
    :returns: One dict per host, or an empty list if *xml_text* is blank.
    :rtype: list[dict]
    :raises xml.etree.ElementTree.ParseError: If the XML is malformed.
    """
    text = (xml_text or "").strip()
    if not text:
        return []
    # Parse with defusedxml: nmap embeds scanned service banners into its XML,
    # so harden against XXE / entity-expansion before trusting the document.
    #
    # nmap2json's public ``nmap_xml_to_json(str)`` is broken in the released
    # build — it calls ``.getroot()`` on the ``Element`` that ``fromstring``
    # returns. Only ``nmap_file_to_json`` (which uses ``ET.parse`` → an
    # ``ElementTree``) works. Wrap the safely-parsed root in an ``ElementTree``
    # and hand it straight to the library's core converter to get the same
    # result without writing the XML to a temp file first.
    root = DET.fromstring(text)
    hosts = nmap_to_json(ET.ElementTree(root))
    _attach_cpes(root, hosts)
    return hosts


def _attach_cpes(root: ET.Element, hosts: list[dict]) -> None:
    """Attach `<service><cpe>` values to each parsed port's service dict.

    nmap2json copies only the ``<service>`` *attributes*, dropping the ``<cpe>``
    child elements. Re-walk the tree and merge CPEs into the matching port's
    ``service`` dict (keyed by address + protocol + portid), so they surface in
    :class:`~portscanner.models.ServiceInfo`.

    :param root: The parsed nmap ``<nmaprun>`` root element.
    :param hosts: The host dicts returned by nmap2json (mutated in place).
    """
    cpe_by_key: dict[tuple[str, str, str], list[str]] = {}
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        if not addr:
            continue
        for port_el in host_el.findall("ports/port"):
            proto = port_el.get("protocol") or ""
            portid = port_el.get("portid") or ""
            cpes = [c.text for c in port_el.findall("service/cpe") if c.text]
            if cpes:
                cpe_by_key[(addr, proto, portid)] = cpes

    if not cpe_by_key:
        return
    for host in hosts:
        addr = host.get("addr")
        for port in host.get("ports") or []:
            key = (addr, port.get("protocol") or "", str(port.get("portid") or ""))
            cpes = cpe_by_key.get(key)
            if cpes and isinstance(port.get("service"), dict):
                port["service"]["cpe"] = cpes


def read_targets_file(path: str) -> list[str]:
    """Read scan targets from a file, one (or more) per line.

    Blank lines and lines beginning with ``#`` are skipped; each remaining line
    is split on whitespace so multiple targets may share a line. Order is
    preserved; de-duplication is left to the caller.

    :param path: Path to the targets file.
    :returns: List of raw (un-validated) target tokens.
    :rtype: list[str]
    :raises ValueError: If the file does not exist or cannot be read.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        raise ValueError(f"Target file not found: {path}")
    except OSError as exc:
        raise ValueError(f"Cannot read target file {path!r}: {exc}")

    targets: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        targets.extend(stripped.split())
    return targets


def _repair_partial_xml(text: str) -> str | None:
    """Best-effort repair of nmap XML truncated by a killed scan.

    nmap streams one ``<host>`` block at a time and only writes the closing
    ``</nmaprun>`` on clean completion, so a killed scan leaves the document
    unterminated (often mid-``<host>``). Keep everything up to the last complete
    ``</host>`` and close the run, so the hosts nmap *did* finish can be parsed.

    :param text: The partial XML captured before the process was killed.
    :returns: A parseable XML string, or ``None`` if no complete host is present.
    :rtype: str | None
    """
    if not text:
        return None
    end = text.rfind("</host>")
    if end == -1:
        return None
    return text[: end + len("</host>")] + "</nmaprun>"


def _parse_partial_xml(text: str) -> list[dict]:
    """Parse possibly-truncated nmap XML, recovering completed hosts.

    Tries the text as-is first (nmap may have flushed a valid footer), then a
    :func:`_repair_partial_xml` fallback. Returns an empty list only when
    nothing parseable remains.

    :param text: Partial nmap XML from a timed-out scan.
    :returns: Host dicts for the hosts that completed before the timeout.
    :rtype: list[dict]
    """
    for candidate in (text, _repair_partial_xml(text)):
        if not candidate:
            continue
        try:
            return parse_nmap_xml(candidate)
        except (ET.ParseError, DefusedXmlException):
            continue
    return []


def build_command(targets: list[str], args: list[str]) -> list[str]:
    """Assemble the full nmap argv for *targets* with pre-built *args*.

    :param targets: The scan targets (hosts, IPs, or CIDR ranges); all are
        passed to a single nmap invocation.
    :param args: Flag list from :func:`build_nmap_args`.
    :returns: Full command list ready for :func:`subprocess.run`.
    :rtype: list[str]
    """
    return ["nmap", *args, "-oX", "-", *targets]


def run_scan(
    targets: list[str],
    *,
    args: list[str],
    timeout: float,
    progress_cb: Callable[[str], None] | None = None,
) -> tuple[list[dict], bool]:
    """Run nmap against *targets* and return parsed hosts plus a timeout flag.

    This is the single mocked boundary in tests. It launches nmap once for all
    targets, captures its XML output on stdout, and parses it via
    :func:`parse_nmap_xml`.

    :param targets: The scan targets (hosts, IPs, or CIDR ranges).
    :param args: nmap flags from :func:`build_nmap_args`.
    :param timeout: Maximum seconds to wait for the whole nmap process.
    :param progress_cb: Optional callback for a progress message before launch.
    :returns: Tuple of (host dicts, ``timed_out``). On timeout, nmap is killed
        and any partial XML captured is parsed on a best-effort basis.
    :rtype: tuple[list[dict], bool]
    :raises RuntimeError: If nmap is not installed, exits non-zero with no
        usable output, or emits XML that cannot be parsed.
    """
    cmd = build_command(targets, args)
    if progress_cb is not None:
        label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
        progress_cb(f"Running nmap against {label}…")
    logger.debug("Executing: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("'nmap' not found – is it installed and on your PATH?")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):  # pragma: no cover – text=True yields str
            partial = partial.decode("utf-8", errors="replace")
        return _parse_partial_xml(partial), True

    if proc.returncode != 0 and not (proc.stdout or "").strip():
        detail = (proc.stderr or "").strip() or f"nmap exited with code {proc.returncode}"
        raise RuntimeError(f"nmap failed: {detail}")

    try:
        return parse_nmap_xml(proc.stdout), False
    except (ET.ParseError, DefusedXmlException) as exc:
        raise RuntimeError(f"could not parse nmap XML output: {exc}")
