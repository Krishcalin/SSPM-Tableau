# CLAUDE.md — Tableau Cloud SSPM Scanner

## Project overview

This is a Python-based **SaaS Security Posture Management (SSPM)** scanner for **Tableau Cloud**. It connects to a live Tableau Cloud instance via the REST API, collects configuration data, evaluates 30 security controls across 5 domains, and generates scored reports.

- **Version**: 0.1.0
- **License**: MIT
- **Python**: 3.10+
- **Dependencies**: `tableauserverclient>=0.30`, `jinja2>=3.0`

## Repository layout

```
src/tableau_sspm/
  checks.py        30 security controls in SecurityChecks class
  cli.py           CLI entrypoint (argparse + env vars)
  collector.py     REST API data collector (tableauserverclient SDK)
  models.py        Finding, ScanResult dataclasses; Severity, Status, Category enums
  report.py        JSON + HTML (Jinja2) report generation
  scoring.py       Severity-weighted posture score calculation

tests/
  conftest.py      Pytest fixtures with mock Tableau data
  test_checks.py   Unit tests for security checks
  test_scoring.py  Unit tests for scoring algorithm
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
pytest -m unit --cov --cov-report=term-missing

# Lint
ruff check src/ tests/
```

Test markers:
- `@pytest.mark.unit` — no API calls, safe to run anywhere
- `@pytest.mark.integration` — requires live Tableau API access

Coverage threshold: 60% (configured in `pyproject.toml`).

## Code conventions

- **Line length**: 120 characters (ruff formatter)
- **Linter**: ruff with E/W/F/I/N/S/B/UP/SIM rules enabled
- **Type checking**: mypy (check_untyped_defs=true)
- `print()` is allowed — this is a CLI tool (T201 suppressed)
- `assert` is allowed in tests (S101 suppressed)

## Scanner architecture

### 3-phase pipeline

1. **Collect** (`collector.py`): Authenticates via PAT, queries 9 REST API endpoints, returns nested dict
2. **Analyze** (`checks.py`): `SecurityChecks.run_all()` evaluates 30 controls, produces `list[Finding]`
3. **Score & Report** (`scoring.py`, `report.py`): Calculates severity-weighted score, writes JSON + HTML

### Adding a new check

1. Add `_check_<name>(self)` method to `SecurityChecks` in `checks.py`
2. Use `self._add(check_id=..., name=..., category=..., severity=..., status=..., ...)` to record finding
3. Call the method from `run_all()`
4. Add unit test in `tests/test_checks.py`

### Check ID format

- `AUTH-NNN` — Identity & Authentication
- `ACCS-NNN` — Access Control & Permissions
- `DATA-NNN` — Data Security
- `API-NNN` — API & Integrations
- `LOG-NNN` — Logging & Monitoring

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
- Docker image runs as non-root `sspm` user
- Exit code 1 if any CRITICAL finding fails **or** score is below `--min-score`
