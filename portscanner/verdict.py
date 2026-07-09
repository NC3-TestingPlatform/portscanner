"""Factual summary of scan results.

No grading, no severity, no recommended actions. Only counts — consistent with
the platform rule that letter grades are reserved for ``mailvalidator`` and
``headersvalidator``.
"""

from __future__ import annotations

from dataclasses import dataclass

from portscanner.models import HostState, PortState, ScanReport


@dataclass
class VerdictSummary:
    """Pure count summary of a :class:`~portscanner.models.ScanReport`.

    :param total_hosts: Number of hosts nmap reported on.
    :param hosts_up: Hosts in the ``up`` state.
    :param hosts_down: Hosts in the ``down`` state.
    :param total_open_ports: Open ports summed across all hosts.
    :param total_ports_reported: All ports nmap reported (any state).
    :param services_identified: Open ports with a non-empty service description.
    :param summary_line: Single human-readable summary string.
    """

    total_hosts: int = 0
    hosts_up: int = 0
    hosts_down: int = 0
    total_open_ports: int = 0
    total_ports_reported: int = 0
    services_identified: int = 0
    summary_line: str = ""


def build_verdict(report: ScanReport) -> VerdictSummary:
    """Compute a :class:`VerdictSummary` from *report*.

    :param report: The completed scan report.
    :returns: A counts-only summary with no scoring or grading.
    :rtype: VerdictSummary
    """
    total_hosts = len(report.hosts)
    hosts_up = sum(1 for h in report.hosts if h.state == HostState.UP)
    hosts_down = sum(1 for h in report.hosts if h.state == HostState.DOWN)

    open_ports = [p for h in report.hosts for p in h.ports if p.state == PortState.OPEN]
    total_open_ports = len(open_ports)
    total_ports_reported = sum(len(h.ports) for h in report.hosts)
    services_identified = sum(
        1 for p in open_ports if p.service is not None and p.service.describe()
    )

    parts = [f"{total_hosts} host{'s' if total_hosts != 1 else ''} scanned"]
    if total_hosts:
        parts.append(f"({hosts_up} up, {hosts_down} down)")
    parts.append(
        f"· {total_open_ports} open port{'s' if total_open_ports != 1 else ''}"
    )
    if services_identified:
        parts.append(f"· {services_identified} service(s) identified")

    return VerdictSummary(
        total_hosts=total_hosts,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        total_open_ports=total_open_ports,
        total_ports_reported=total_ports_reported,
        services_identified=services_identified,
        summary_line=" ".join(parts),
    )
