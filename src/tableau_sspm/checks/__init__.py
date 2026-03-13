"""Security control checks — 30 controls across 5 domains."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .identity import IdentityChecks
from .access import AccessControlChecks
from .data import DataSecurityChecks
from .api import APIChecks
from .logging_checks import LoggingChecks

if TYPE_CHECKING:
    from ..models import Finding

logger = logging.getLogger(__name__)

_CHECK_SUITES = [
    ("identity", IdentityChecks),
    ("access control", AccessControlChecks),
    ("data security", DataSecurityChecks),
    ("API & integration", APIChecks),
    ("logging & monitoring", LoggingChecks),
]


class SecurityChecks:
    """Evaluates collected data against security controls.

    This class is the public entry-point and delegates to per-domain
    check suites.  It preserves the same interface as the original
    monolithic version so callers need no changes.
    """

    def __init__(self, data: dict) -> None:
        self.data = data
        self.findings: list[Finding] = []

    def run_all(self) -> list[Finding]:
        for label, suite_cls in _CHECK_SUITES:
            logger.info("Running %s checks...", label)
            suite = suite_cls(self.data)
            self.findings.extend(suite.run())
        logger.info("%d checks completed", len(self.findings))
        return self.findings


__all__ = [
    "SecurityChecks",
    "IdentityChecks",
    "AccessControlChecks",
    "DataSecurityChecks",
    "APIChecks",
    "LoggingChecks",
]
