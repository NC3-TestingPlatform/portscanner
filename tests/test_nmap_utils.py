"""Tests for command building, XML parsing, and the nmap subprocess boundary."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from portscanner import nmap_utils
from portscanner.nmap_utils import (
    build_command,
    build_nmap_args,
    parse_nmap_xml,
    run_scan,
)


# --- build_nmap_args --------------------------------------------------------


def test_build_args_default():
    assert build_nmap_args() == ["-sT", "-sV", "-T4"]


def test_build_args_without_service_detection():
    assert build_nmap_args(service_detection=False) == ["-sT", "-T4"]


def test_build_args_skip_ping():
    assert "-Pn" in build_nmap_args(skip_ping=True)


def test_build_args_ports():
    args = build_nmap_args(ports="22,80,443")
    assert "-p" in args and "22,80,443" in args


def test_build_args_top_ports():
    args = build_nmap_args(top_ports=100)
    assert "--top-ports" in args and "100" in args


def test_build_args_host_timeout_and_retries():
    args = build_nmap_args(host_timeout=30, max_retries=2)
    assert "--host-timeout" in args and "30s" in args
    assert "--max-retries" in args and "2" in args


def test_build_args_rejects_bad_timing():
    with pytest.raises(ValueError):
        build_nmap_args(timing=6)
    with pytest.raises(ValueError):
        build_nmap_args(timing=-1)


def test_build_args_rejects_ports_and_top_ports():
    with pytest.raises(ValueError):
        build_nmap_args(ports="22", top_ports=10)


def test_build_command_shape():
    assert build_command("host", ["-sT"]) == ["nmap", "-sT", "-oX", "-", "host"]


# --- parse_nmap_xml ---------------------------------------------------------


def test_parse_empty_returns_empty_list():
    assert parse_nmap_xml("   ") == []


def test_parse_sample(sample_xml):
    hosts = parse_nmap_xml(sample_xml)
    assert len(hosts) == 1
    assert hosts[0]["addr"] == "45.33.32.156"
    assert hosts[0]["status"]["state"] == "up"
    assert len(hosts[0]["ports"]) == 2


# --- run_scan ---------------------------------------------------------------


def test_run_scan_success(mocker, sample_xml):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout=sample_xml, stderr=""),
    )
    hosts, timed_out = run_scan("host", args=["-sT"], timeout=10)
    assert timed_out is False
    assert hosts[0]["addr"] == "45.33.32.156"


def test_run_scan_invokes_progress_cb(mocker, sample_xml):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout=sample_xml, stderr=""),
    )
    seen = []
    run_scan("host", args=["-sT"], timeout=10, progress_cb=seen.append)
    assert seen and "host" in seen[0]


def test_run_scan_missing_binary(mocker):
    mocker.patch.object(nmap_utils.subprocess, "run", side_effect=FileNotFoundError)
    with pytest.raises(RuntimeError, match="not found"):
        run_scan("host", args=["-sT"], timeout=10)


def test_run_scan_nonzero_with_no_output(mocker):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    )
    with pytest.raises(RuntimeError, match="boom"):
        run_scan("host", args=["-sT"], timeout=10)


def test_run_scan_malformed_xml(mocker):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout="<not-valid", stderr=""),
    )
    with pytest.raises(RuntimeError, match="parse"):
        run_scan("host", args=["-sT"], timeout=10)


def test_run_scan_timeout_returns_partial_flag(mocker):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1),
    )
    hosts, timed_out = run_scan("host", args=["-sT"], timeout=1)
    assert timed_out is True
    assert hosts == []


def test_run_scan_timeout_parses_partial_xml(mocker, sample_xml):
    mocker.patch.object(
        nmap_utils.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(
            cmd=["nmap"], timeout=1, output=sample_xml
        ),
    )
    hosts, timed_out = run_scan("host", args=["-sT"], timeout=1)
    assert timed_out is True
    assert hosts and hosts[0]["addr"] == "45.33.32.156"
