# Contributing to Tableau Cloud SSPM

## Getting Started

```bash
git clone https://github.com/your-org/tableau-sspm.git
cd tableau-sspm
make dev          # installs package + dev deps + pre-commit hooks
make test         # runs unit tests
```

## Adding a New Security Check

1. Open `src/tableau_sspm/checks.py`
2. Add a method to the `SecurityChecks` class:

```python
def _check_my_new_control(self):
    data = self.data.get("users", [])
    # ... evaluation logic ...
    self._add(
        check_id="DOMAIN-NNN",
        name="Human-Readable Name",
        category=Category.IDENTITY,
        severity=Severity.HIGH,
        status=Status.FAIL,
        details="What was found",
        description="Why this matters",
        remediation="How to fix it",
        evidence=["item1", "item2"],
    )
```

3. Register it in `run_all()` under the appropriate domain section
4. Add test cases in `tests/test_checks.py`
5. Run `make test` to verify

## Conventions

- **Check IDs**: `AUTH-NNN`, `ACCS-NNN`, `DATA-NNN`, `API-NNN`, `LOG-NNN`
- **Severity**: Use `CRITICAL` only for controls that, if failed, directly enable data breach or account takeover
- **Evidence**: Include specific resource names (users, datasources) — capped at 20 items
- **Remediation**: Actionable steps, not just "fix this". Include specific Tableau settings paths.

## Code Quality

- Run `make lint` before committing (or rely on pre-commit hooks)
- All checks must have corresponding unit tests
- Tests must pass with `pytest -m unit` (no API access required)

## Pull Request Process

1. Create a feature branch from `main`
2. Add tests for any new checks or logic
3. Ensure `make lint && make test` passes
4. Open a PR with a clear description of what the check does and why it matters
5. Include the check ID and severity in the PR title (e.g., "Add AUTH-007: SSO Session Duration Check (HIGH)")
