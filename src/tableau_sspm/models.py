"""Shared data models, enums, and constants."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    SKIP = "skip"


class Category(str, Enum):
    IDENTITY = "Identity & Authentication"
    ACCESS = "Access Control & Permissions"
    DATA = "Data Security"
    API = "API & Integrations"
    LOGGING = "Logging & Monitoring"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    check_id: str
    name: str
    category: str
    severity: str
    status: str
    description: str
    remediation: str
    details: str = ""
    evidence: list = field(default_factory=list)


@dataclass
class ScanResult:
    scan_id: str
    scan_time: str
    server: str
    site: str
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    errors: int = 0
    skipped: int = 0
    score: float = 0.0
    findings: list = field(default_factory=list)
    category_scores: dict = field(default_factory=dict)
    raw_stats: dict = field(default_factory=dict)
