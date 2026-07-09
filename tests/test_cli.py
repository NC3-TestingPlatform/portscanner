"""Tests for the Typer CLI (check / info / --version)."""

from __future__ import annotations

import json

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


def test_check_multiple_targets(mocker, sample_report):
    spy = mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "a.example", "b.example"])
    assert result.exit_code == 0
    passed, kwargs = spy.call_args
    assert passed[0] == ["a.example", "b.example"]
    assert kwargs["target_file"] is None


def test_check_target_file(mocker, sample_report, tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("a.example\nb.example\n")
    spy = mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "--target-file", str(f)])
    assert result.exit_code == 0
    _, kwargs = spy.call_args
    assert kwargs["target_file"] == str(f)


def test_check_rustscan_flag(mocker, sample_report):
    spy = mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "1.2.3.4", "--rustscan"])
    assert result.exit_code == 0
    _, kwargs = spy.call_args
    assert kwargs["rustscan"] is True


def test_check_rustscan_tuning(mocker, sample_report):
    spy = mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(
        app,
        ["check", "1.2.3.4", "--rustscan", "--rustscan-batch", "5000", "--rustscan-ports", "1-1000"],
    )
    assert result.exit_code == 0
    _, kwargs = spy.call_args
    assert kwargs["rustscan_batch"] == 5000
    assert kwargs["rustscan_ports"] == "1-1000"


def test_check_rustscan_with_ports_exit_1():
    # assess() raises ValueError before any subprocess runs → exit 1
    result = runner.invoke(app, ["check", "1.2.3.4", "--rustscan", "-p", "22"])
    assert result.exit_code == 1


def test_check_no_targets_and_no_file_exit_1():
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 1


def test_check_missing_target_file_exit_1():
    result = runner.invoke(app, ["check", "-iL", "/no/such/targets.txt"])
    assert result.exit_code == 1


def test_check_json_valid_with_long_command(mocker, sample_report):
    # A long (two-phase) command must not be word-wrapped into invalid JSON.
    sample_report.command = (
        "rustscan -a scanme.nmap.org --greppable --range 1-65535 --batch-size 5000 "
        "&& nmap -sT -sV -p 22,80,443,8080,8443 -T4 -oX - scanme.nmap.org"
    )
    mocker.patch.object(cli, "assess", return_value=sample_report)
    result = runner.invoke(app, ["check", "scanme.nmap.org", "--rustscan", "--json"])
    assert result.exit_code == 0
    # Isolate the JSON object (the CliRunner merges the stderr progress spinner
    # into output); it must parse — i.e. no newline was wrapped into a string.
    out = result.output
    data = json.loads(out[out.index("{") : out.rindex("}") + 1])
    assert data["command"] == sample_report.command


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


def test_check_keyboard_interrupt_exit_130(mocker):
    mocker.patch.object(cli, "assess", side_effect=KeyboardInterrupt)
    result = runner.invoke(app, ["check", "host"])
    assert result.exit_code == 130
