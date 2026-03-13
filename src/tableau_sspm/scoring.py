"""Posture score calculation.

Severity-weighted scoring: Critical (25), High (15), Medium (8), Low (3).
PASS = full weight, WARN = 50%, FAIL = 0%.
"""

from .models import Finding, Status, SEVERITY_WEIGHT


def calculate_score(findings: list[Finding]) -> tuple[float, dict]:
    """Return (overall_score, {category: score}) from a list of findings."""
    total_weight = 0
    earned_weight = 0
    category_weights: dict[str, dict] = {}

    for f in findings:
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        total_weight += w

        cat = f.category
        if cat not in category_weights:
            category_weights[cat] = {"total": 0, "earned": 0}
        category_weights[cat]["total"] += w

        if f.status == Status.PASS:
            earned_weight += w
            category_weights[cat]["earned"] += w
        elif f.status == Status.WARN:
            earned_weight += w * 0.5
            category_weights[cat]["earned"] += w * 0.5

    overall = round((earned_weight / total_weight) * 100, 1) if total_weight > 0 else 0
    cat_scores = {
        cat: round((v["earned"] / v["total"]) * 100, 1) if v["total"] > 0 else 0
        for cat, v in category_weights.items()
    }
    return overall, cat_scores
