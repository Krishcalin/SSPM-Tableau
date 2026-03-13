# CLAUDE.md — Tableau Cloud SSPM Scanner

## Project overview

This is a Python-based **SaaS Security Posture Management (SSPM)** scanner for **Tableau Cloud**. It connects to a live Tableau Cloud instance via the REST API, collects configuration data, evaluates 45 security controls across 5 domains, and generates scored reports.

- **Version**: 0.1.0
- **License**: MIT
- **Python**: 3.10+
- **Dependencies**: `tableauserverclient>=0.30`, `jinja2>=3.0`

## Repository layout

```
src/tableau_sspm/
  __init__.py          Public API exports
  checks/              45 security controls (modular architecture)
    __init__.py        SecurityChecks orchestrator + _CHECK_SUITES
    base.py            BaseChecks ABC (abstract run(), _add() helper)
    identity.py        AUTH-001 to AUTH-009 (IdP, stale, admin, domains, roles, service accounts)
    access.py          ACCS-001 to ACCS-009 (permissions, guest, groups, derived, hierarchy, ownership)
    data.py            DATA-001 to DATA-009 (credentials, encryption, naming, certification, bridge)
    api.py             API-001 to API-009 (extensions, flows, alerts, Ask Data)
    logging_checks.py  LOG-001 to LOG-009 (catalog, visibility, admin mode, site state)
  cli.py               CLI entrypoint (argparse + env vars + logging)
  collector.py         REST API collector (retry, timeout, TSC SDK)
  models.py            Finding, ScanResult dataclasses; Severity, Status, Category enums
  report.py            JSON + HTML (Jinja2) report generation
  scoring.py           Severity-weighted posture score calculation

tests/
  conftest.py          Pytest fixtures with mock Tableau data
  test_checks.py       58 unit tests for all 45 security checks
  test_scoring.py      Unit tests for scoring algorithm
```

## Build and run

```bash
# Install
pip install -e .

# Dev setup (includes ruff, pytest, mypy, pre-commit)
pip install -e ".[dev]"
pre-commit install

# Run scanner (requires Tableau Cloud PAT)
tableau-sspm --server <URL> --site <SITE> --token-name <NAME> --token-secret <SECRET>

# Or via env vars
export TABLEAU_SERVER=... TABLEAU_SITE=... TABLEAU_TOKEN_NAME=... TABLEAU_TOKEN_SECRET=...
tableau-sspm
```

## Testing

```bash
# Unit tests
pytest -m unit -v

# With coverage
pytest -m unit --cov=tableau_sspm --cov-report=term-missing --cov-fail-under=80

# Lint
ruff check src/ tests/
```

Test markers:
- `@pytest.mark.unit` — no API calls, safe to run anywhere
- `@pytest.mark.integration` — requires live Tableau API access

Coverage threshold: 80% (enforced in CI).

## Code conventions

- **Line length**: 120 characters (ruff formatter)
- **Linter**: ruff with E/W/F/I/N/S/B/UP/SIM rules enabled
- **Type checking**: mypy (disallow_untyped_defs=true)
- **Logging**: `logging` module everywhere; `print()` only in `cli.py` for console UI (T201 per-file ignore)
- `assert` is allowed in tests (S101 suppressed)

## Scanner architecture

### 3-phase pipeline

1. **Collect** (`collector.py`): Authenticates via PAT, queries 9 REST API endpoints, returns nested dict (exponential backoff retry, configurable timeouts)
2. **Analyze** (`checks/`): `SecurityChecks.run_all()` delegates to 5 domain suites (9 controls each = 45 total), produces `list[Finding]`
3. **Score & Report** (`scoring.py`, `report.py`): Calculates severity-weighted score, writes JSON + HTML

### Adding a new check

1. Add `_check_<name>(self) -> None` method to the appropriate domain suite in `checks/`
2. Use `self._add(check_id=..., name=..., category=..., severity=..., status=..., ...)` to record finding
3. Call the method from the suite's `run()` method
4. Add unit test in `tests/test_checks.py`
5. Update `TestFullScan.test_run_all_returns_45_findings` count if adding a new check

### Check ID format

- `AUTH-NNN` — Identity & Authentication (identity.py)
- `ACCS-NNN` — Access Control & Permissions (access.py)
- `DATA-NNN` — Data Security (data.py)
- `API-NNN` — API & Integrations (api.py)
- `LOG-NNN` — Logging & Monitoring (logging_checks.py)

### Severity weights

| Severity | Weight | Use when |
|----------|--------|----------|
| CRITICAL | 25 | Direct breach or account-takeover risk |
| HIGH | 15 | Significant security gap |
| MEDIUM | 8 | Governance or configuration weakness |
| LOW | 3 | Best practice improvement |
| INFO | 0 | Informational only |

### Status values

- `PASS` — control satisfied (full weight earned)
- `FAIL` — control violated (0 weight)
- `WARN` — partial compliance (50% weight)
- `SKIP` — not evaluable (excluded from score)
- `ERROR` — check execution failed

## Important notes

- The scanner is **read-only** — it never modifies the Tableau Cloud environment
- PAT secrets must never be committed; use `.env` (gitignored) or CI/CD secrets
- The HTML report uses a dark theme with embedded CSS (no external dependencies)
- Docker image is SHA-pinned with HEALTHCHECK, runs as non-root `sspm` user
- Exit code 1 if any CRITICAL finding fails **or** score is below `--min-score`
- CI includes pip-audit for dependency vulnerability scanning and Dependabot for automated updates
