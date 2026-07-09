"""Tests for the high-level assess() orchestration and dict→model conversion."""

from __future__ import annotations

import pytest

from portscanner import assessor
from portscanner.assessor import _to_host, assess
from portscanner.models import HostState, PortState


def test_assess_converts_hosts(mocker, sample_hosts):
    mocker.patch.object(assessor, "run_scan", return_value=(sample_hosts, False))
    report = assess("scanme.nmap.org", top_ports=100)

    assert report.target == "scanme.nmap.org"
    assert report.timed_out is False
    assert "nmap" in report.command
    assert len(report.hosts) == 1

    host = report.hosts[0]
    assert host.address == "45.33.32.156"
    assert host.state == HostState.UP
    assert [p.port for p in host.open_ports] == [22]

    ssh = host.ports[0]
    assert ssh.state == PortState.OPEN
    assert ssh.service.describe() == "OpenSSH 6.6.1p1 (Ubuntu)"


def test_assess_passes_args_and_timeout(mocker, sample_hosts):
    spy = mocker.patch.object(assessor, "run_scan", return_value=(sample_hosts, False))
    assess("host", ports="22,80", timeout=42.0)
    _, kwargs = spy.call_args
    assert kwargs["timeout"] == 42.0
    assert "-p" in kwargs["args"] and "22,80" in kwargs["args"]


def test_assess_propagates_timed_out(mocker):
    mocker.patch.object(assessor, "run_scan", return_value=([], True))
    report = assess("host")
    assert report.timed_out is True
    assert report.hosts == []


def test_assess_multiple_targets(mocker):
    spy = mocker.patch.object(assessor, "run_scan", return_value=([], False))
    report = assess(["a.example", "b.example", "10.0.0.0/24"])
    assert report.targets == ["a.example", "b.example", "10.0.0.0/24"]
    passed_targets, _ = spy.call_args
    assert passed_targets[0] == ["a.example", "b.example", "10.0.0.0/24"]
    assert "a.example" in report.command and "10.0.0.0/24" in report.command


def test_assess_dedupes_targets(mocker):
    mocker.patch.object(assessor, "run_scan", return_value=([], False))
    report = assess(["a.example", "a.example", "b.example"])
    assert report.targets == ["a.example", "b.example"]


def test_assess_reads_target_file(mocker, tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# hosts\nfile-a.example\nfile-b.example\n")
    mocker.patch.object(assessor, "run_scan", return_value=([], False))
    report = assess(["cli.example"], target_file=str(f))
    assert report.targets == ["cli.example", "file-a.example", "file-b.example"]


def test_assess_missing_target_file_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        assess(["a.example"], target_file=str(tmp_path / "nope.txt"))


def test_assess_invalid_target_raises_value_error():
    with pytest.raises(ValueError, match="Invalid target"):
        assess(["bad target"])


def test_assess_no_targets_raises_value_error():
    with pytest.raises(ValueError):
        assess([])


def test_assess_empty_target_raises_value_error():
    with pytest.raises(ValueError):
        assess("   ")


def test_assess_invalid_timing_raises_value_error():
    with pytest.raises(ValueError):
        assess("host", timing=9)


def test_assess_ports_and_top_ports_raises_value_error():
    with pytest.raises(ValueError):
        assess("host", ports="22", top_ports=10)


def test_to_host_minimal_dict():
    host = _to_host({"addr": "1.2.3.4"})
    assert host.address == "1.2.3.4"
    assert host.state == HostState.UNKNOWN
    assert host.ports == []
    assert host.hostnames == []


def test_to_host_sorts_ports():
    raw = {
        "addr": "1.2.3.4",
        "ports": [
            {"portid": "443", "protocol": "tcp", "state": {"state": "open"}},
            {"portid": "22", "protocol": "tcp", "state": {"state": "open"}},
        ],
    }
    host = _to_host(raw)
    assert [p.port for p in host.ports] == [22, 443]
