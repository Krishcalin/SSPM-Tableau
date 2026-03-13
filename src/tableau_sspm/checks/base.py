"""Base class for security check suites."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding


class BaseChecks(ABC):
    """Abstract base for a domain-specific check suite."""

    def __init__(self, data: dict) -> None:
        self.data = data
        self.findings: list[Finding] = []

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute all checks in this suite and return findings."""

    def _add(self, **kwargs: object) -> None:
        self.findings.append(Finding(**kwargs))
