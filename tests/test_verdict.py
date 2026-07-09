"""Tests for the counts-only verdict summary."""

from __future__ import annotations

from portscanner.models import (
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
)
from portscanner.verdict import build_verdict


def _report() -> ScanReport:
    up_host = HostResult(
        address="10.0.0.1",
        state=HostState.UP,
        ports=[
            PortResult(22, "tcp", PortState.OPEN, service=ServiceInfo(product="OpenSSH", version="9")),
            PortResult(80, "tcp", PortState.OPEN),
            PortResult(443, "tcp", PortState.CLOSED),
        ],
    )
    down_host = HostResult(address="10.0.0.2", state=HostState.DOWN)
    return ScanReport(target="10.0.0.0/30", hosts=[up_host, down_host])


def test_verdict_counts():
    v = build_verdict(_report())
    assert v.total_hosts == 2
    assert v.hosts_up == 1
    assert v.hosts_down == 1
    assert v.total_open_ports == 2
    assert v.total_ports_reported == 3
    assert v.services_identified == 1  # only the SSH port has a description


def test_verdict_summary_line_mentions_counts():
    v = build_verdict(_report())
    assert "2 hosts scanned" in v.summary_line
    assert "2 open ports" in v.summary_line


def test_verdict_empty_report():
    v = build_verdict(ScanReport(target="x"))
    assert v.total_hosts == 0
    assert v.total_open_ports == 0
    assert "0 host" in v.summary_line
