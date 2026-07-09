"""Tests for the result dataclasses and enums."""

from __future__ import annotations

from portscanner.models import (
    HostResult,
    HostState,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
)


def test_portstate_from_nmap_known():
    assert PortState.from_nmap("open") is PortState.OPEN
    assert PortState.from_nmap("open|filtered") is PortState.OPEN_FILTERED


def test_portstate_from_nmap_unknown():
    assert PortState.from_nmap("weird") is PortState.UNKNOWN


def test_portstate_from_nmap_none():
    assert PortState.from_nmap(None) is PortState.UNKNOWN


def test_service_describe_full():
    svc = ServiceInfo(product="OpenSSH", version="9.6p1", extrainfo="Ubuntu")
    assert svc.describe() == "OpenSSH 9.6p1 (Ubuntu)"


def test_service_describe_extrainfo_only():
    assert ServiceInfo(extrainfo="Ubuntu").describe() == "Ubuntu"


def test_service_describe_empty():
    assert ServiceInfo().describe() == ""


def test_service_describe_product_only():
    assert ServiceInfo(product="nginx").describe() == "nginx"


def test_host_open_ports_filters_by_state():
    host = HostResult(
        address="10.0.0.1",
        ports=[
            PortResult(22, "tcp", PortState.OPEN),
            PortResult(23, "tcp", PortState.CLOSED),
            PortResult(80, "tcp", PortState.OPEN),
        ],
    )
    assert [p.port for p in host.open_ports] == [22, 80]


def test_scan_report_defaults():
    report = ScanReport(target="example.com")
    assert report.hosts == []
    assert report.timed_out is False
    assert report.error is None


def test_host_state_enum_values():
    assert HostState.UP.value == "up"
    assert HostState.DOWN.value == "down"
