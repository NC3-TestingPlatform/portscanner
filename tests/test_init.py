"""Tests for package metadata and logging setup."""

from __future__ import annotations

import logging

import portscanner


def test_version_is_nonempty_string():
    assert isinstance(portscanner.__version__, str)
    assert portscanner.__version__


def test_logger_has_null_handler():
    logger = logging.getLogger("portscanner")
    assert any(isinstance(h, logging.NullHandler) for h in logger.handlers)
