"""Tests for the tool registry and availability detection."""

from __future__ import annotations

from portscanner import constants


def test_required_tools_contains_nmap():
    assert "nmap" in constants.REQUIRED_TOOLS
    assert constants.REQUIRED_TOOLS["nmap"]["binary"] == "nmap"


def test_detect_tools_keys_match_registry():
    detected = constants.detect_tools()
    assert set(detected) == set(constants.REQUIRED_TOOLS)
    assert all(isinstance(v, bool) for v in detected.values())


def test_get_install_hint_known_tool():
    assert "nmap" in constants.get_install_hint("nmap")


def test_get_install_hint_unknown_tool():
    hint = constants.get_install_hint("masscan")
    assert "masscan" in hint
    assert "PATH" in hint
