"""Port scanning – nmap-driven port/service inventory via nmap2json parsing."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("portscanner")
except PackageNotFoundError:  # pragma: no cover – only when package not installed
    __version__ = "0.5.1"

# NullHandler so library users who have not configured logging
# do not see "No handler found" warnings (logging HOWTO).
import logging as _logging

_logging.getLogger("portscanner").addHandler(_logging.NullHandler())
del _logging

__all__ = ["__version__"]
