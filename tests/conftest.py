"""Shared pytest fixtures for portscanner tests.

The sample XML is a trimmed, synthetic nmap ``-oX`` document (no real scan
data). It exercises the shapes the parser cares about: an up host with a
hostname, an open port with full service/version detection, and a closed port
with only a table-based service guess.
"""

from __future__ import annotations

import pytest

from portscanner.assessor import _to_host
from portscanner.models import ScanReport
from portscanner.nmap_utils import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - scanme.nmap.org" start="1700000000" version="7.99">
  <host starttime="1700000000" endtime="1700000100">
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="53"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>
        </service>
        <script id="ssh-hostkey" output="2048 SHA256:redacted"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="conn-refused" reason_ttl="0"/>
        <service name="https" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.fixture
def sample_xml() -> str:
    """Return the synthetic nmap XML document as a string."""
    return SAMPLE_XML


@pytest.fixture
def sample_hosts() -> list[dict]:
    """Return the nmap2json-parsed host dicts for :data:`SAMPLE_XML`."""
    return parse_nmap_xml(SAMPLE_XML)


@pytest.fixture
def sample_report(sample_hosts: list[dict]) -> ScanReport:
    """Return a :class:`ScanReport` built from the sample hosts."""
    hosts = [_to_host(h) for h in sample_hosts]
    return ScanReport(
        targets=["scanme.nmap.org"],
        command="nmap -sT -sV -oX - scanme.nmap.org",
        hosts=hosts,
    )
