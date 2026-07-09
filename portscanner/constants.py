"""Tool registry, defaults, and availability detection for portscanner.

:data:`REQUIRED_TOOLS` maps short tool names to the metadata needed to locate
the binary and display installation hints. Unlike ``subdomainenum`` (which
wraps many interchangeable tools), portscanner needs exactly one external
binary — ``nmap`` — plus the pure-Python ``nmap2json`` library, which is a
declared package dependency rather than a PATH binary.
"""

from __future__ import annotations

import re
import shutil

# Lenient target matcher: hostnames, IPv4/IPv6 literals, and CIDR ranges all
# use only these characters. Targets are passed to nmap as subprocess arguments
# (never through a shell), so this guards against obviously malformed input
# (embedded whitespace, shell metacharacters) rather than shell injection.
TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")

# External binaries the module can shell out to. ``nmap`` is required; ``rustscan``
# is optional and only used by the ``--rustscan`` fast-discovery mode (a TCP
# connect scan — no root needed). nmap2json is NOT listed here: it is a Python
# dependency (see pyproject.toml), imported directly, not run as a subprocess.
REQUIRED_TOOLS: dict[str, dict[str, str]] = {
    "nmap": {
        "binary": "nmap",
        "install": "apt install nmap  # or: dnf install nmap / brew install nmap",
    },
    "rustscan": {
        "binary": "rustscan",
        "install": "cargo install rustscan  # optional, for --rustscan; or github.com/RustScan/RustScan/releases (no root needed)",
    },
}

# Default nmap scan parameters. The default profile is a TCP connect scan
# (``-sT``) with service/version detection (``-sV``) so it works without root
# privileges (no raw-socket SYN scan). Timing template T4 balances speed and
# reliability on typical networks.
DEFAULT_TIMING = 4
MIN_TIMING = 0
MAX_TIMING = 5

# Per-process subprocess timeout for a single scanner invocation, in seconds.
# Generous by default because service/version detection (-sV) and especially
# NSE scripts (-sC) across many ports can be slow; scans that still exceed it
# are killed and (in rustscan mode) fall back to the discovered port list.
DEFAULT_TIMEOUT = 900.0


def detect_tools() -> dict[str, bool]:
    """Return a mapping of tool name → availability on the current ``PATH``.

    :returns: Dict where keys are tool names from :data:`REQUIRED_TOOLS` and
        values are ``True`` if the binary was found, ``False`` otherwise.
    :rtype: dict[str, bool]
    """
    return {
        name: shutil.which(info["binary"]) is not None
        for name, info in REQUIRED_TOOLS.items()
    }


def get_install_hint(name: str) -> str:
    """Return the install hint string for a tool.

    :param name: Tool name (key in :data:`REQUIRED_TOOLS`).
    :returns: Install command string, or a generic hint for unknown tools.
    :rtype: str
    """
    info = REQUIRED_TOOLS.get(name)
    if info:
        return info["install"]
    return f"Install '{name}' manually and ensure it is on your PATH."
