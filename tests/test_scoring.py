"""Unit tests for posture score calculation."""

import pytest
from tableau_sspm.scoring import calculate_score
from tableau_sspm.models import Finding, Status, Severity, Category


@pytest.mark.unit
def test_all_pass_scores_100():
    findings = [
        Finding("T-001", "Test", Category.IDENTITY, Severity.CRITICAL, Status.PASS, "", "", ""),
        Finding("T-002", "Test", Category.IDENTITY, Severity.HIGH, Status.PASS, "", "", ""),
    ]
    score, _ = calculate_score(findings)
    assert score == 100.0


@pytest.mark.unit
def test_all_fail_scores_0():
    findings = [
        Finding("T-001", "Test", Category.IDENTITY, Severity.CRITICAL, Status.FAIL, "", "", ""),
        Finding("T-002", "Test", Category.ACCESS, Severity.HIGH, Status.FAIL, "", "", ""),
    ]
    score, _ = calculate_score(findings)
    assert score == 0.0


@pytest.mark.unit
def test_warn_earns_half_weight():
    findings = [
        Finding("T-001", "Test", Category.IDENTITY, Severity.HIGH, Status.WARN, "", "", ""),
    ]
    score, _ = calculate_score(findings)
    assert score == 50.0


@pytest.mark.unit
def test_category_scores_independent():
    findings = [
        Finding("T-001", "Test", Category.IDENTITY, Severity.CRITICAL, Status.PASS, "", "", ""),
        Finding("T-002", "Test", Category.DATA, Severity.CRITICAL, Status.FAIL, "", "", ""),
    ]
    _, cat_scores = calculate_score(findings)
    assert cat_scores[Category.IDENTITY] == 100.0
    assert cat_scores[Category.DATA] == 0.0


@pytest.mark.unit
def test_severity_weighting():
    # Critical fail + Low pass should score better than Critical fail + Critical pass would if reversed
    findings = [
        Finding("T-001", "Test", Category.IDENTITY, Severity.CRITICAL, Status.FAIL, "", "", ""),
        Finding("T-002", "Test", Category.IDENTITY, Severity.LOW, Status.PASS, "", "", ""),
    ]
    score, _ = calculate_score(findings)
    # 0 + 3 earned out of 25 + 3 = 28 total → ~10.7%
    assert score < 15


@pytest.mark.unit
def test_empty_findings():
    score, cat_scores = calculate_score([])
    assert score == 0
    assert cat_scores == {}


@pytest.mark.unit
def test_full_scan_score_range(full_scan_data):
    from tableau_sspm.checks import SecurityChecks
    checks = SecurityChecks(full_scan_data)
    findings = checks.run_all()
    score, cat_scores = calculate_score(findings)
    # With our fixture data, score should be somewhere reasonable
    assert 0 <= score <= 100
    assert len(cat_scores) == 5
