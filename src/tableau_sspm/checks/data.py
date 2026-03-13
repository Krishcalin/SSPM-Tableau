"""Data Security checks (DATA-001 through DATA-009)."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ..models import Finding, Status, Severity, Category
from .base import BaseChecks


class DataSecurityChecks(BaseChecks):
    """9 checks covering credentials, encryption, sensitive naming, certification, downloads, staleness, bridge, connections, and governance."""

    def run(self) -> list[Finding]:
        self._check_embedded_credentials()
        self._check_extract_encryption()
        self._check_sensitive_datasource_names()
        self._check_datasource_certification()
        self._check_data_download_surface()
        self._check_stale_datasources()
        self._check_remote_query_agent()
        self._check_multi_connection_datasources()
        self._check_uncertified_in_sensitive_projects()
        return self.findings

    def _check_embedded_credentials(self) -> None:
        datasources = self.data.get("datasources", [])
        embedded = []
        for ds in datasources:
            for conn in ds.get("connections", []):
                if conn.get("embed_password") is True:
                    embedded.append({
                        "datasource": ds["name"],
                        "connection_type": conn.get("connection_type"),
                        "username": conn.get("username"),
                    })

        if not embedded:
            status = Status.PASS
            details = "No data sources with embedded credentials detected"
        elif len(embedded) <= 2:
            status = Status.WARN
            details = f"{len(embedded)} data source(s) have embedded credentials"
        else:
            status = Status.FAIL
            details = f"{len(embedded)} data sources embed database credentials — significant credential exposure"

        self._add(
            check_id="DATA-001", name="Embedded Credentials Audit",
            category=Category.DATA, severity=Severity.CRITICAL,
            status=status, details=details,
            description="Embedded credentials in data sources mean database passwords are stored in Tableau. Prefer OAuth or prompt-based auth.",
            remediation="Republish data sources with 'Prompt user' or OAuth delegation. Use service accounts with minimal DB privileges if embedding is unavoidable.",
            evidence=[f"{e['datasource']} → {e['connection_type']} (user: {e['username']})" for e in embedded[:20]],
        )

    def _check_extract_encryption(self) -> None:
        settings = self.data.get("site_settings", {})
        mode = settings.get("extract_encryption_mode")

        if mode is None:
            status = Status.WARN
            details = "Extract encryption mode not retrievable — Tableau Cloud encrypts at rest by default"
        elif mode == "enforced":
            status = Status.PASS
            details = "Extract encryption is enforced"
        else:
            status = Status.WARN
            details = f"Extract encryption mode: {mode} — verify meets compliance requirements"

        self._add(
            check_id="DATA-002", name="Extract Encryption at Rest",
            category=Category.DATA, severity=Severity.HIGH,
            status=status, details=details,
            description="Extracts stored in Tableau Cloud should be encrypted at rest. For regulated data, consider customer-managed encryption keys (CMEK).",
            remediation="Tableau Cloud uses AES-256 encryption by default. For CMEK, configure via Salesforce Shield platform encryption.",
            evidence=[],
        )

    def _check_sensitive_datasource_names(self) -> None:
        datasources = self.data.get("datasources", [])
        sensitive_patterns = [
            "pii", "ssn", "social security", "credit card", "password", "secret",
            "salary", "compensation", "phi", "hipaa", "medical", "patient",
            "confidential", "restricted", "internal only", "private",
        ]
        flagged = []
        for ds in datasources:
            name_lower = (ds["name"] or "").lower()
            for pattern in sensitive_patterns:
                if pattern in name_lower:
                    flagged.append({"name": ds["name"], "pattern": pattern, "certified": ds.get("is_certified", False)})
                    break

        if not flagged:
            status = Status.PASS
            details = "No data sources with sensitive naming patterns detected"
        else:
            uncertified = [f for f in flagged if not f["certified"]]
            status = Status.WARN if len(uncertified) == 0 else Status.FAIL
            details = f"{len(flagged)} data source(s) have names suggesting sensitive data ({len(uncertified)} uncertified)"

        self._add(
            check_id="DATA-003", name="Sensitive Data Source Naming",
            category=Category.DATA, severity=Severity.HIGH,
            status=status, details=details,
            description="Data sources with names suggesting sensitive content (PII, PHI, credentials) should be classified and protected.",
            remediation="Apply data labels via Tableau Catalog. Ensure sensitive data sources have RLS, are certified, and reside in locked projects.",
            evidence=[f"{f['name']} (pattern: '{f['pattern']}', certified: {f['certified']})" for f in flagged[:15]],
        )

    def _check_datasource_certification(self) -> None:
        datasources = self.data.get("datasources", [])
        if not datasources:
            status = Status.SKIP
            details = "No data sources found"
        else:
            certified = [ds for ds in datasources if ds.get("is_certified")]
            ratio = len(certified) / len(datasources)
            if ratio >= 0.5:
                status = Status.PASS
                details = f"{len(certified)}/{len(datasources)} data sources are certified ({ratio:.0%})"
            elif ratio >= 0.2:
                status = Status.WARN
                details = f"Only {len(certified)}/{len(datasources)} data sources certified ({ratio:.0%})"
            else:
                status = Status.FAIL
                details = f"Low certification rate: {len(certified)}/{len(datasources)} ({ratio:.0%})"

        self._add(
            check_id="DATA-004", name="Data Source Certification Coverage",
            category=Category.DATA, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Certifying trusted data sources helps users distinguish governed from ungoverned data.",
            remediation="Establish a certification process. Data stewards should certify sources that are accurate, maintained, and governed.",
            evidence=[],
        )

    def _check_data_download_surface(self) -> None:
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])
        total_content = len(workbooks) + len(datasources)

        if total_content == 0:
            status = Status.SKIP
            details = "No content to assess"
        elif total_content > 50:
            status = Status.WARN
            details = f"{total_content} content items — high data download surface area. Review download permissions."
        else:
            status = Status.PASS
            details = f"{total_content} content items — manageable surface area"

        self._add(
            check_id="DATA-005", name="Data Download Surface Area",
            category=Category.DATA, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Users with download permissions can exfiltrate underlying data. Restrict download rights on sensitive content.",
            remediation="Deny 'Download Full Data' and 'Download Summary Data' on sensitive projects. Audit via Admin Insights download events.",
            evidence=[],
        )

    def _check_stale_datasources(self) -> None:
        datasources = self.data.get("datasources", [])
        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=180)
        stale = []
        for ds in datasources:
            updated = ds.get("updated_at")
            if updated:
                try:
                    dt = datetime.fromisoformat(updated)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if dt < threshold:
                        stale.append(ds)
                except (ValueError, TypeError):
                    pass

        if not stale:
            status = Status.PASS
            details = "No data sources stale for >180 days"
        elif len(stale) <= 5:
            status = Status.WARN
            details = f"{len(stale)} data sources not updated in 180+ days"
        else:
            status = Status.FAIL
            details = f"{len(stale)} stale data sources (>180 days) — potential data quality and security risk"

        self._add(
            check_id="DATA-006", name="Stale Data Source Detection",
            category=Category.DATA, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Data sources not updated in >6 months may contain outdated security configurations or orphaned credentials.",
            remediation="Review stale data sources with owners. Remove or archive unused sources. Check for embedded credentials in stale sources.",
            evidence=[f"{ds['name']} (last updated: {ds['updated_at']})" for ds in stale[:15]],
        )

    def _check_remote_query_agent(self) -> None:
        datasources = self.data.get("datasources", [])
        bridge_ds = [ds for ds in datasources if ds.get("use_remote_query_agent") is True]

        if not bridge_ds:
            status = Status.PASS
            details = "No data sources use Tableau Bridge / Remote Query Agent"
        elif len(bridge_ds) <= 5:
            status = Status.WARN
            details = f"{len(bridge_ds)} data sources use Tableau Bridge — ensure Bridge agents are patched and firewalled"
        else:
            status = Status.WARN
            details = f"{len(bridge_ds)} data sources use Tableau Bridge — significant on-prem attack surface"

        self._add(
            check_id="DATA-007", name="Remote Query Agent / Bridge Usage",
            category=Category.DATA, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Tableau Bridge connects Cloud to on-prem data. Bridge agents run in your network and must be secured, patched, and monitored.",
            remediation="Inventory Bridge agents. Ensure agents run as service accounts with minimal access. Keep Bridge up to date. Restrict outbound to Tableau Cloud IPs.",
            evidence=[f"{ds['name']} ({ds.get('datasource_type', 'unknown')})" for ds in bridge_ds[:15]],
        )

    def _check_multi_connection_datasources(self) -> None:
        datasources = self.data.get("datasources", [])
        multi_conn = [ds for ds in datasources if len(ds.get("connections", [])) > 1]

        if not multi_conn:
            status = Status.PASS
            details = "No data sources with multiple connections"
        else:
            status = Status.WARN
            details = f"{len(multi_conn)} data sources have multiple connections — broader credential and network exposure"

        self._add(
            check_id="DATA-008", name="Multi-Connection Data Sources",
            category=Category.DATA, severity=Severity.LOW,
            status=status, details=details,
            description="Data sources with multiple connections cross-join data from different systems, expanding credential exposure and complicating access audits.",
            remediation="Review multi-connection data sources. Ensure each connection uses least-privilege credentials. Document cross-system data flows.",
            evidence=[f"{ds['name']} ({len(ds.get('connections', []))} connections)" for ds in multi_conn[:15]],
        )

    def _check_uncertified_in_sensitive_projects(self) -> None:
        datasources = self.data.get("datasources", [])
        projects = self.data.get("projects", [])

        sensitive_keywords = ["finance", "hr", "pii", "confidential", "restricted", "compliance", "legal", "hipaa", "pci", "sox"]
        sensitive_project_ids = set()
        sensitive_project_names: dict[str, str] = {}
        for p in projects:
            name_lower = (p.get("name") or "").lower()
            for kw in sensitive_keywords:
                if kw in name_lower:
                    sensitive_project_ids.add(p["id"])
                    sensitive_project_names[p["id"]] = p["name"]
                    break

        uncertified: list[dict] = []
        if not sensitive_project_ids:
            status = Status.PASS
            details = "No projects with sensitive naming patterns detected"
        else:
            uncertified = [
                ds for ds in datasources
                if ds.get("project_id") in sensitive_project_ids and not ds.get("is_certified")
            ]
            if not uncertified:
                status = Status.PASS
                details = f"All data sources in {len(sensitive_project_ids)} sensitive project(s) are certified"
            else:
                status = Status.FAIL
                details = f"{len(uncertified)} uncertified data sources in sensitive projects — governance gap"

        self._add(
            check_id="DATA-009", name="Uncertified Sources in Sensitive Projects",
            category=Category.DATA, severity=Severity.HIGH,
            status=status, details=details,
            description="Data sources in projects with sensitive names (Finance, HR, PII) should be certified to ensure they are governed and trustworthy.",
            remediation="Certify all data sources in sensitive projects. Assign data stewards. Require certification before publishing to governed projects.",
            evidence=[f"{ds['name']} in {sensitive_project_names.get(ds.get('project_id'), 'unknown')}" for ds in uncertified[:15]],
        )
