"""Tableau Cloud SSPM — SaaS Security Posture Management Scanner."""

__version__ = "0.1.0"

from .models import Category, Finding, ScanResult, Severity, Status
from .checks import SecurityChecks
from .collector import TableauCollector
from .scoring import calculate_score
from .report import generate_html_report, generate_json_report

__all__ = [
    "__version__",
    "Category",
    "Finding",
    "ScanResult",
    "Severity",
    "Status",
    "SecurityChecks",
    "TableauCollector",
    "calculate_score",
    "generate_html_report",
    "generate_json_report",
]
