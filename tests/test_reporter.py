"""Tests for JSON serialization and Rich rendering."""

from __future__ import annotations

import pytest
from rich.console import Console

from portscanner.reporter import print_full_report, save_report, to_dict


def test_to_dict_structure(sample_report):
    data = to_dict(sample_report)
    assert data["target"] == "scanme.nmap.org"
    assert data["timed_out"] is False
    assert len(data["hosts"]) == 1

    host = data["hosts"][0]
    assert host["address"] == "45.33.32.156"
    assert host["state"] == "up"
    assert host["hostnames"] == ["scanme.nmap.org"]

    ssh = host["ports"][0]
    assert ssh["port"] == 22
    assert ssh["state"] == "open"
    assert ssh["service"]["product"] == "OpenSSH"


def test_print_full_report_contains_key_facts(sample_report):
    con = Console(record=True, width=120)
    print_full_report(sample_report, console=con)
    text = con.export_text()
    assert "scanme.nmap.org" in text
    assert "22" in text
    assert "ssh" in text
    assert "OpenSSH" in text
    assert "Summary" in text


def test_print_full_report_no_hosts():
    from portscanner.models import ScanReport

    con = Console(record=True, width=120)
    print_full_report(ScanReport(target="nohosts.example"), console=con)
    text = con.export_text()
    assert "No hosts reported" in text


def test_save_report_rejects_unknown_extension():
    with pytest.raises(ValueError, match="extension"):
        save_report("report.pdf")


def test_save_report_writes_text_file(tmp_path, sample_report):
    # print_full_report to the module console so save_report has content
    print_full_report(sample_report)
    out = tmp_path / "report.txt"
    save_report(str(out))
    assert out.exists()
    assert out.read_text().strip()


def test_save_report_html(tmp_path, sample_report):
    print_full_report(sample_report)
    out = tmp_path / "report.html"
    save_report(str(out))
    assert out.exists()
    assert "<html" in out.read_text().lower()
