"""Tests for the masscan boundary: arg building, parsing, resolution, run."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from portscanner import masscan_utils
from portscanner.masscan_utils import (
    build_masscan_args,
    parse_masscan_list,
    resolve_targets,
    run_scan_masscan,
)

SAMPLE_MASSCAN = (
    "#masscan\n"
    "open tcp 22 45.33.32.156 1783584930\n"
    "open tcp 80 45.33.32.156 1783584930\n"
    "# end\n"
)


# --- build_masscan_args -----------------------------------------------------


def test_build_masscan_args():
    assert build_masscan_args(ports="1-65535", rate=1000) == [
        "-p",
        "1-65535",
        "--rate",
        "1000",
    ]


# --- parse_masscan_list -----------------------------------------------------


def test_parse_masscan_list_sample():
    assert parse_masscan_list(SAMPLE_MASSCAN) == [22, 80]


def test_parse_masscan_list_dedupes_and_sorts():
    text = "open tcp 443 1.1.1.1 0\nopen tcp 22 1.1.1.1 0\nopen tcp 443 2.2.2.2 0\n"
    assert parse_masscan_list(text) == [22, 443]


def test_parse_masscan_list_ignores_malformed_and_empty():
    assert parse_masscan_list("") == []
    assert parse_masscan_list("garbage line\nopen tcp notaport 1.1.1.1 0\n") == []


# --- resolve_targets --------------------------------------------------------


def test_resolve_targets_passes_through_ip_and_cidr():
    assert resolve_targets(["10.0.0.1", "192.168.0.0/24"]) == [
        "10.0.0.1",
        "192.168.0.0/24",
    ]


def test_resolve_targets_resolves_hostnames(mocker):
    mocker.patch.object(
        masscan_utils.socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", ("45.33.32.156", 0))],
    )
    assert resolve_targets(["scanme.nmap.org"]) == ["45.33.32.156"]


def test_resolve_targets_dedupes(mocker):
    mocker.patch.object(
        masscan_utils.socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", ("1.2.3.4", 0)), (2, 1, 6, "", ("1.2.3.4", 0))],
    )
    assert resolve_targets(["host", "1.2.3.4"]) == ["1.2.3.4"]


def test_resolve_targets_skips_unresolvable(mocker):
    mocker.patch.object(
        masscan_utils.socket, "getaddrinfo", side_effect=OSError("nope")
    )
    assert resolve_targets(["no-such-host.invalid"]) == []


# --- run_scan_masscan -------------------------------------------------------


def _fake_run(content, returncode=0, stderr=""):
    """Return a subprocess.run stand-in that writes *content* to the -oL file."""

    def _run(cmd, **kwargs):
        out_path = cmd[cmd.index("-oL") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)

    return _run


def test_run_masscan_success(mocker):
    mocker.patch.object(masscan_utils, "resolve_targets", return_value=["45.33.32.156"])
    mocker.patch.object(
        masscan_utils.subprocess, "run", side_effect=_fake_run(SAMPLE_MASSCAN)
    )
    ports, command = run_scan_masscan(["scanme.nmap.org"], timeout=10)
    assert ports == [22, 80]
    assert command.startswith("masscan ") and "-oL -" in command


def test_run_masscan_permission_failure(mocker):
    mocker.patch.object(masscan_utils, "resolve_targets", return_value=["1.2.3.4"])
    mocker.patch.object(
        masscan_utils.subprocess,
        "run",
        side_effect=_fake_run("", returncode=1, stderr="FAIL: permission denied"),
    )
    with pytest.raises(RuntimeError, match="permission denied"):
        run_scan_masscan(["1.2.3.4"], timeout=10)


def test_run_masscan_missing_binary(mocker):
    mocker.patch.object(masscan_utils, "resolve_targets", return_value=["1.2.3.4"])
    mocker.patch.object(
        masscan_utils.subprocess, "run", side_effect=FileNotFoundError
    )
    with pytest.raises(RuntimeError, match="not found"):
        run_scan_masscan(["1.2.3.4"], timeout=10)


def test_run_masscan_no_resolved_targets(mocker):
    mocker.patch.object(masscan_utils, "resolve_targets", return_value=[])
    with pytest.raises(RuntimeError, match="could not resolve"):
        run_scan_masscan(["bad.invalid"], timeout=10)


def test_run_masscan_timeout_returns_empty(mocker):
    mocker.patch.object(masscan_utils, "resolve_targets", return_value=["1.2.3.4"])
    mocker.patch.object(
        masscan_utils.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd=["masscan"], timeout=1),
    )
    ports, command = run_scan_masscan(["1.2.3.4"], timeout=1)
    assert ports == []
    assert "masscan" in command
