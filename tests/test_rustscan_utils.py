"""Tests for the rustscan boundary: arg building, greppable parsing, run."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from portscanner import rustscan_utils
from portscanner.rustscan_utils import (
    build_rustscan_args,
    parse_rustscan_greppable,
    run_scan_rustscan,
)

SAMPLE_GREP = "45.33.32.156 -> [22,80]\n"


# --- build_rustscan_args ----------------------------------------------------


def test_build_args_default_greppable_only():
    assert build_rustscan_args() == ["--greppable"]


def test_build_args_range_spec():
    assert build_rustscan_args(ports="1-65535") == ["--greppable", "--range", "1-65535"]


def test_build_args_list_spec():
    assert build_rustscan_args(ports="80,443") == ["--greppable", "--ports", "80,443"]


def test_build_args_single_port_uses_ports():
    assert build_rustscan_args(ports="80") == ["--greppable", "--ports", "80"]


def test_build_args_tuning():
    args = build_rustscan_args(batch=5000, port_timeout=1500, ulimit=5000)
    assert "--batch-size" in args and "5000" in args
    assert "--timeout" in args and "1500" in args
    assert "--ulimit" in args


# --- parse_rustscan_greppable -----------------------------------------------


def test_parse_greppable_sample():
    assert parse_rustscan_greppable(SAMPLE_GREP) == [22, 80]


def test_parse_greppable_unions_hosts_and_sorts():
    text = "1.1.1.1 -> [443,22]\n2.2.2.2 -> [80,443]\n"
    assert parse_rustscan_greppable(text) == [22, 80, 443]


def test_parse_greppable_empty_and_no_open():
    assert parse_rustscan_greppable("") == []
    assert parse_rustscan_greppable("1.1.1.1 -> []\n") == []


# --- run_scan_rustscan ------------------------------------------------------


def test_run_rustscan_success(mocker):
    mocker.patch.object(
        rustscan_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout=SAMPLE_GREP, stderr=""),
    )
    ports, command = run_scan_rustscan(["scanme.nmap.org"], timeout=10)
    assert ports == [22, 80]
    assert command.startswith("rustscan -a scanme.nmap.org")
    assert "--greppable" in command


def test_run_rustscan_nonzero_but_ports_found(mocker):
    # rustscan can exit non-zero yet still report open ports — trust the output
    mocker.patch.object(
        rustscan_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=1, stdout=SAMPLE_GREP, stderr=""),
    )
    ports, _ = run_scan_rustscan(["1.2.3.4"], timeout=10)
    assert ports == [22, 80]


def test_run_rustscan_no_ports_clean_exit(mocker):
    mocker.patch.object(
        rustscan_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stdout="no ports here", stderr=""),
    )
    ports, _ = run_scan_rustscan(["1.2.3.4"], timeout=10)
    assert ports == []


def test_run_rustscan_error_raises(mocker):
    mocker.patch.object(
        rustscan_utils.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=2, stdout="", stderr="bad --flag"),
    )
    with pytest.raises(RuntimeError, match="rustscan failed"):
        run_scan_rustscan(["1.2.3.4"], timeout=10)


def test_run_rustscan_missing_binary(mocker):
    mocker.patch.object(rustscan_utils.subprocess, "run", side_effect=FileNotFoundError)
    with pytest.raises(RuntimeError, match="not found"):
        run_scan_rustscan(["1.2.3.4"], timeout=10)


def test_run_rustscan_timeout_parses_partial(mocker):
    mocker.patch.object(
        rustscan_utils.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(
            cmd=["rustscan"], timeout=1, output=SAMPLE_GREP
        ),
    )
    ports, _ = run_scan_rustscan(["1.2.3.4"], timeout=1)
    assert ports == [22, 80]
