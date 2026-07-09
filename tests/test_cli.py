"""Tests for the Typer CLI (check / info / --version)."""

from __future__ import annotations

from typer.testing import CliRunner

from portscanner import cli
from portscanner.cli import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "portscanner" in result.output


def test_info_command():
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "nmap" in result.output


def test_check_prints_report(mocker, sample_report):
    mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "scanme.nmap.org"])
    assert result.exit_code == 0
    assert "scanme.nmap.org" in result.output


def test_check_json_output(mocker, sample_report):
    mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "scanme.nmap.org", "--json"])
    assert result.exit_code == 0
    assert '"target": "scanme.nmap.org"' in result.output


def test_check_writes_output_file(mocker, sample_report, tmp_path):
    mocker.patch.object(cli, "assess", return_value=sample_report)
    out = tmp_path / "r.txt"
    result = runner.invoke(app, ["check", "host", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()


def test_check_invalid_target():
    result = runner.invoke(app, ["check", "bad target!"])
    assert result.exit_code == 2  # Click usage error for a bad argument


def test_check_ports_and_top_ports_mutually_exclusive():
    result = runner.invoke(app, ["check", "host", "-p", "22", "--top-ports", "10"])
    assert result.exit_code == 1


def test_check_value_error_exit_1(mocker):
    mocker.patch.object(cli, "assess", side_effect=ValueError("bad input"))
    result = runner.invoke(app, ["check", "host"])
    assert result.exit_code == 1


def test_check_runtime_error_exit_2(mocker):
    mocker.patch.object(cli, "assess", side_effect=RuntimeError("nmap exploded"))
    result = runner.invoke(app, ["check", "host"])
    assert result.exit_code == 2
