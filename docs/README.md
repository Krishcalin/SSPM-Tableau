# Tableau Cloud SSPM Scanner

A SaaS Security Posture Management tool for Tableau Cloud. Connects to your Tableau Cloud instance via the REST API, pulls live configuration data, and evaluates **30 security controls** across 5 domains.

## Security Controls

| Domain | Controls | What's Checked |
|--------|----------|---------------|
| **Identity & Authentication** | 6 | IdP federation, stale accounts, admin sprawl, auth consistency |
| **Access Control & Permissions** | 6 | Over-privileged users, locked permissions, guest access, group-based access |
| **Data Security** | 6 | Embedded credentials, extract encryption, sensitive data naming, certification, stale sources |
| **API & Integrations** | 6 | Extension allowlist, revision history, subscribe-others, flows, content sprawl |
| **Logging & Monitoring** | 6 | Catalog, user visibility, commenting, access review readiness, orphaned content |

Each control has:
- **Severity weighting** (Critical → Low) that feeds the overall posture score
- **Evidence collection** with specific user/resource names
- **Actionable remediation** guidance

## Prerequisites

1. **Tableau Cloud site** with admin access
2. **Personal Access Token (PAT)** — create one in Tableau Cloud:
   - Go to **My Account Settings → Personal Access Tokens**
   - Create a token and save the **name** and **secret**
   - The PAT user must have **Site Administrator Creator** role
3. **Python 3.10+**

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### CLI Arguments

```bash
python scanner.py \
  --server https://prod-apsoutheast-a.online.tableau.com \
  --site my-site \
  --token-name my-pat-name \
  --token-secret <YOUR_PAT_SECRET>
```

### Environment Variables

```bash
export TABLEAU_SERVER=https://prod-apsoutheast-a.online.tableau.com
export TABLEAU_SITE=my-site
export TABLEAU_TOKEN_NAME=my-pat-name
export TABLEAU_TOKEN_SECRET=<YOUR_PAT_SECRET>

python scanner.py
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `$TABLEAU_SERVER` | Tableau Cloud pod URL |
| `--site` | `$TABLEAU_SITE` | Site content URL (from your Tableau URL) |
| `--token-name` | `$TABLEAU_TOKEN_NAME` | PAT name |
| `--token-secret` | `$TABLEAU_TOKEN_SECRET` | PAT secret value |
| `--output-dir` | `./sspm_output` | Where to write reports |
| `--json-only` | `false` | Skip HTML report, output JSON only |

## Output

The scanner produces two reports in `--output-dir`:

- **`SSPM-YYYYMMDD-HHMMSS.json`** — Machine-readable findings with full evidence
- **`SSPM-YYYYMMDD-HHMMSS.html`** — Visual report with posture score, findings, and remediation

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No critical failures |
| `1` | One or more CRITICAL-severity checks failed |

This makes it CI/CD friendly — you can gate deployments on posture score.

## Scoring

The posture score (0–100) is severity-weighted:

| Severity | Weight |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |

- **PASS** = full weight earned
- **WARN** = 50% weight earned
- **FAIL** = 0 weight earned

Score interpretation:
- **85+** → Strong posture
- **65–84** → Moderate — address high/critical findings
- **40–64** → Weak — significant gaps
- **<40** → Critical — immediate remediation required

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Tableau SSPM Scan
  env:
    TABLEAU_SERVER: ${{ secrets.TABLEAU_SERVER }}
    TABLEAU_SITE: ${{ secrets.TABLEAU_SITE }}
    TABLEAU_TOKEN_NAME: ${{ secrets.TABLEAU_TOKEN_NAME }}
    TABLEAU_TOKEN_SECRET: ${{ secrets.TABLEAU_TOKEN_SECRET }}
  run: |
    pip install -r requirements.txt
    python scanner.py --output-dir ./sspm-results
```

## Extending

To add a new check, add a method to the `SecurityChecks` class in `scanner.py`:

```python
def _check_my_new_control(self):
    data = self.data.get("users", [])
    # ... evaluation logic ...
    self._add(
        check_id="DOMAIN-NNN",
        name="Human-Readable Name",
        category=Category.IDENTITY,  # or ACCESS, DATA, API, LOGGING
        severity=Severity.HIGH,
        status=Status.FAIL,  # or PASS, WARN, SKIP
        details="What was found",
        description="Why this matters",
        remediation="How to fix it",
        evidence=["item1", "item2"],
    )
```

Then call it from `run_all()`.

## API Endpoints Used

The scanner uses these Tableau REST API resources (read-only):

- `GET /api/3.x/sites/{siteId}/users` — User enumeration and roles
- `GET /api/3.x/sites/{siteId}/groups` — Group membership
- `GET /api/3.x/sites/{siteId}/projects` — Project structure and permissions
- `GET /api/3.x/sites/{siteId}/datasources` — Data source configurations
- `GET /api/3.x/sites/{siteId}/datasources/{dsId}/connections` — Connection details
- `GET /api/3.x/sites/{siteId}/workbooks` — Workbook inventory
- `GET /api/3.x/sites/{siteId}/schedules` — Extract refresh schedules
- `GET /api/3.x/sites/{siteId}/flows` — Prep flow inventory
- `GET /api/3.x/sites/{siteId}` — Site settings

No write operations are performed. The PAT only needs read access.
