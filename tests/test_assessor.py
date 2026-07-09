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


def test_assess_scripts_flag_adds_sc(mocker, sample_hosts):
    spy = mocker.patch.object(assessor, "run_scan", return_value=(sample_hosts, False))
    assess(["scanme.nmap.org"], scripts=True)
    _, kwargs = spy.call_args
    assert "-sC" in kwargs["args"]


def test_assess_surfaces_cpe_and_scripts(mocker, sample_hosts):
    mocker.patch.object(assessor, "run_scan", return_value=(sample_hosts, False))
    report = assess(["scanme.nmap.org"])
    ssh = next(p for p in report.hosts[0].ports if p.port == 22)
    assert ssh.service.cpe == ["cpe:/a:openbsd:openssh:6.6.1p1"]
    assert any(s.get("id") == "ssh-hostkey" for s in ssh.scripts)


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


def test_assess_rejects_leading_dash_target():
    # Argument-injection guard: a target that looks like a flag must be rejected.
    for bad in ("-oX", "--script", "-iL"):
        with pytest.raises(ValueError, match="Invalid target"):
            assess([bad])


def test_assess_rejects_leading_dash_from_target_file(mocker, tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("good.example\n-oX\n")
    with pytest.raises(ValueError, match="Invalid target"):
        assess([], target_file=str(f))


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


def test_assess_rustscan_then_nmap(mocker, sample_hosts):
    mocker.patch.object(
        assessor,
        "run_scan_rustscan",
        return_value=({"45.33.32.156": [22, 80]}, "rustscan -a scanme"),
    )
    nmap_spy = mocker.patch.object(
        assessor, "run_scan", return_value=(sample_hosts, False)
    )
    report = assessor.assess(["scanme.nmap.org"], rustscan=True)

    # nmap must be restricted to exactly the ports rustscan discovered
    _, kwargs = nmap_spy.call_args
    assert "-p" in kwargs["args"]
    assert kwargs["args"][kwargs["args"].index("-p") + 1] == "22,80"
    # rustscan already established liveness → nmap phase must force -Pn so
    # ping-blocking hosts are not dropped.
    assert "-Pn" in kwargs["args"]
    assert "rustscan" in report.command and "nmap" in report.command
    assert len(report.hosts) == 1


def test_assess_rustscan_no_open_ports_skips_nmap(mocker):
    mocker.patch.object(
        assessor, "run_scan_rustscan", return_value=({}, "rustscan -a 1.2.3.4")
    )
    nmap_spy = mocker.patch.object(assessor, "run_scan")
    report = assessor.assess(["1.2.3.4"], rustscan=True)

    nmap_spy.assert_not_called()
    assert report.hosts == []
    assert report.command == "rustscan -a 1.2.3.4"


def test_assess_rustscan_passes_tuning(mocker):
    spy = mocker.patch.object(
        assessor, "run_scan_rustscan", return_value=({}, "rustscan")
    )
    assessor.assess(
        ["1.2.3.4"],
        rustscan=True,
        rustscan_batch=5000,
        rustscan_timeout=1500,
        rustscan_ports="1-1000",
        rustscan_ulimit=5000,
    )
    _, kwargs = spy.call_args
    assert kwargs["batch"] == 5000
    assert kwargs["port_timeout"] == 1500
    assert kwargs["ports"] == "1-1000"
    assert kwargs["ulimit"] == 5000


def test_assess_ipv6_target_adds_dash6(mocker):
    spy = mocker.patch.object(assessor, "run_scan", return_value=([], False))
    assess(["2001:db8::1"])
    passed_targets, kwargs = spy.call_args
    assert passed_targets[0] == ["2001:db8::1"]
    assert "-6" in kwargs["args"]


def test_assess_mixed_family_splits_into_two_nmap_runs(mocker):
    spy = mocker.patch.object(assessor, "run_scan", return_value=([], False))
    assess(["10.0.0.1", "2001:db8::1"])
    assert spy.call_count == 2
    by_family = {("-6" in kw["args"]): args[0] for args, kw in spy.call_args_list}
    assert by_family[False] == ["10.0.0.1"]   # IPv4 group, no -6
    assert by_family[True] == ["2001:db8::1"]  # IPv6 group, -6


def test_assess_rustscan_per_host_targeting(mocker):
    # Two hosts with different open ports → one nmap run per port-set, each
    # scanning only its host for only its ports.
    mocker.patch.object(
        assessor,
        "run_scan_rustscan",
        return_value=({"10.0.0.1": [22], "10.0.0.2": [443]}, "rustscan"),
    )
    spy = mocker.patch.object(assessor, "run_scan", return_value=([], False))
    assess(["10.0.0.1", "10.0.0.2"], rustscan=True)
    assert spy.call_count == 2
    runs = {tuple(args[0]): kw["args"] for args, kw in spy.call_args_list}
    assert runs[("10.0.0.1",)][runs[("10.0.0.1",)].index("-p") + 1] == "22"
    assert runs[("10.0.0.2",)][runs[("10.0.0.2",)].index("-p") + 1] == "443"


def test_assess_rustscan_with_ports_raises(mocker):
    with pytest.raises(ValueError, match="rustscan"):
        assessor.assess(["1.2.3.4"], rustscan=True, ports="22")


def test_assess_rustscan_with_top_ports_raises(mocker):
    with pytest.raises(ValueError, match="rustscan"):
        assessor.assess(["1.2.3.4"], rustscan=True, top_ports=100)


def test_assess_merges_same_ip_hosts(mocker):
    # Two DNS names resolving to one IP → nmap emits two host blocks with the
    # same addr. They must coalesce into a single host with merged hostnames.
    raw = [
        {
            "addr": "31.22.122.93",
            "hostnames": [{"name": "nc3.lu", "type": "user"}],
            "status": {"state": "up"},
            "ports": [
                {"portid": "80", "protocol": "tcp", "state": {"state": "open"}},
            ],
        },
        {
            "addr": "31.22.122.93",
            "hostnames": [{"name": "cybersecurity.lu", "type": "user"}],
            "status": {"state": "up"},
            "ports": [
                {"portid": "443", "protocol": "tcp", "state": {"state": "open"}},
            ],
        },
    ]
    mocker.patch.object(assessor, "run_scan", return_value=(raw, False))
    report = assess(["nc3.lu", "cybersecurity.lu"])

    assert len(report.hosts) == 1
    host = report.hosts[0]
    assert host.address == "31.22.122.93"
    assert host.hostnames == ["nc3.lu", "cybersecurity.lu"]
    assert [p.port for p in host.ports] == [80, 443]


def test_assess_merge_prefers_open_port(mocker):
    # Same IP, same port reported closed in one block and open in another →
    # the merged port must be open (with its service detail).
    raw = [
        {
            "addr": "10.0.0.1",
            "status": {"state": "up"},
            "ports": [{"portid": "80", "protocol": "tcp", "state": {"state": "closed"}}],
        },
        {
            "addr": "10.0.0.1",
            "status": {"state": "up"},
            "ports": [
                {
                    "portid": "80",
                    "protocol": "tcp",
                    "state": {"state": "open"},
                    "service": {"name": "http"},
                }
            ],
        },
    ]
    mocker.patch.object(assessor, "run_scan", return_value=(raw, False))
    report = assess(["10.0.0.1"])
    assert len(report.hosts) == 1
    ports = report.hosts[0].ports
    assert len(ports) == 1
    assert ports[0].state == PortState.OPEN
    assert ports[0].service is not None and ports[0].service.name == "http"


def test_assess_merge_adopts_up_state(mocker):
    # First block for the IP is down (no ports); a later block is up → merged
    # host must be up and carry the discovered ports.
    raw = [
        {"addr": "10.0.0.1", "status": {"state": "down"}, "ports": []},
        {
            "addr": "10.0.0.1",
            "status": {"state": "up", "reason": "syn-ack"},
            "ports": [{"portid": "22", "protocol": "tcp", "state": {"state": "open"}}],
        },
    ]
    mocker.patch.object(assessor, "run_scan", return_value=(raw, False))
    report = assess(["10.0.0.1"])
    assert len(report.hosts) == 1
    host = report.hosts[0]
    assert host.state == HostState.UP
    assert host.reason == "syn-ack"
    assert [p.port for p in host.ports] == [22]


def test_assess_does_not_merge_addressless_hosts(mocker):
    # Hosts with no address must not be collapsed together.
    raw = [
        {"addr": None, "status": {"state": "up"}, "ports": []},
        {"addr": None, "status": {"state": "up"}, "ports": []},
    ]
    mocker.patch.object(assessor, "run_scan", return_value=(raw, False))
    report = assess(["10.0.0.1"])
    assert len(report.hosts) == 2


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
