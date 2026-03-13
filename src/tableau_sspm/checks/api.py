"""API & Integrations checks (API-001 through API-009)."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ..models import Finding, Status, Severity, Category
from .base import BaseChecks


class APIChecks(BaseChecks):
    """9 checks covering extensions, revision history, subscriptions, flows, content sprawl, stale flows, alerts, and Ask Data."""

    def run(self) -> list[Finding]:
        self._check_extension_surface()
        self._check_revision_history()
        self._check_subscribe_others()
        self._check_run_now_enabled()
        self._check_flow_security()
        self._check_content_sprawl()
        self._check_stale_flows()
        self._check_data_driven_alerts()
        self._check_ask_data_mode()
        return self.findings

    def _check_extension_surface(self) -> None:
        workbooks = self.data.get("workbooks", [])
        status = Status.WARN
        details = f"{len(workbooks)} workbooks may use dashboard extensions — verify allowlist is configured"

        self._add(
            check_id="API-001", name="Dashboard Extension Allowlist",
            category=Category.API, severity=Severity.HIGH,
            status=status, details=details,
            description="Dashboard extensions can execute arbitrary code. Only approved extensions should be permitted via allowlist.",
            remediation="Settings → Extensions → enable allowlist. Add only vetted extensions. Prefer sandboxed over network-enabled extensions.",
            evidence=[],
        )

    def _check_revision_history(self) -> None:
        settings = self.data.get("site_settings", {})
        enabled = settings.get("revision_history_enabled")
        limit = settings.get("revision_limit")

        if enabled is None:
            status = Status.WARN
            details = "Revision history setting not retrievable — verify manually"
        elif enabled:
            status = Status.PASS
            details = f"Revision history enabled (limit: {limit or 'default'})"
        else:
            status = Status.FAIL
            details = "Revision history is DISABLED — no change tracking for content"

        self._add(
            check_id="API-002", name="Revision History for Change Tracking",
            category=Category.API, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Revision history enables rollback and audit trail for content changes.",
            remediation="Enable revision history in Site Settings. Set a reasonable limit (e.g., 25 revisions) to balance storage and auditability.",
            evidence=[],
        )

    def _check_subscribe_others(self) -> None:
        settings = self.data.get("site_settings", {})
        enabled = settings.get("subscribe_others_enabled")

        if enabled is None:
            status = Status.WARN
            details = "Subscribe-others setting not retrievable"
        elif enabled:
            status = Status.WARN
            details = "Users can subscribe others to email reports — potential data leakage vector"
        else:
            status = Status.PASS
            details = "Subscribe-others is disabled"

        self._add(
            check_id="API-003", name="Subscribe Others Control",
            category=Category.API, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Allowing users to subscribe others sends dashboard snapshots via email, which may leak sensitive data.",
            remediation="Disable 'subscribe others' in Site Settings unless needed. If enabled, monitor subscription activity via Admin Insights.",
            evidence=[],
        )

    def _check_run_now_enabled(self) -> None:
        settings = self.data.get("site_settings", {})
        enabled = settings.get("run_now_enabled")

        if enabled is None:
            status = Status.WARN
            details = "Run Now setting not retrievable"
        elif enabled:
            status = Status.WARN
            details = "Run Now is enabled — users can trigger extract refreshes on demand"
        else:
            status = Status.PASS
            details = "Run Now is disabled — extracts follow scheduled refresh only"

        self._add(
            check_id="API-004", name="Run Now Access Control",
            category=Category.API, severity=Severity.LOW,
            status=status, details=details,
            description="Run Now allows users to trigger extract refreshes outside schedules, potentially impacting performance and bypassing refresh windows.",
            remediation="Disable Run Now for non-admin users if you need strict refresh scheduling. Low severity but relevant for governance.",
            evidence=[],
        )

    def _check_flow_security(self) -> None:
        flows = self.data.get("flows", [])

        if not flows:
            status = Status.PASS
            details = "No flows configured"
        else:
            status = Status.WARN
            details = f"{len(flows)} flows found — ensure flow outputs are governed and credentials reviewed"

        self._add(
            check_id="API-005", name="Prep Flow Security Review",
            category=Category.API, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Tableau Prep flows can read, transform, and write data. Flow credentials and output destinations must be governed.",
            remediation="Audit flow output destinations. Ensure flow credentials use service accounts. Restrict flow publishing to governed projects.",
            evidence=[f"{f['name']} (project: {f.get('project_name', 'N/A')})" for f in flows[:15]],
        )

    def _check_content_sprawl(self) -> None:
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])
        projects = self.data.get("projects", [])

        total = len(workbooks) + len(datasources)
        ratio = total / max(len(projects), 1)

        if ratio <= 20:
            status = Status.PASS
            details = f"Content-to-project ratio: {ratio:.0f}:1 — well-organized"
        elif ratio <= 50:
            status = Status.WARN
            details = f"Content-to-project ratio: {ratio:.0f}:1 — consider more project structure"
        else:
            status = Status.FAIL
            details = f"Content-to-project ratio: {ratio:.0f}:1 — content sprawl risk"

        self._add(
            check_id="API-006", name="Content Sprawl Assessment",
            category=Category.API, severity=Severity.LOW,
            status=status, details=details,
            description="High content-to-project ratios indicate ungoverned content sprawl, making permission management difficult.",
            remediation="Create a hierarchical project structure. Migrate content from flat/Default projects into governed folders. Archive unused content.",
            evidence=[f"Workbooks: {len(workbooks)}, Data Sources: {len(datasources)}, Projects: {len(projects)}"],
        )

    def _check_stale_flows(self) -> None:
        flows = self.data.get("flows", [])
        if not flows:
            self._add(
                check_id="API-007", name="Stale Flow Detection",
                category=Category.API, severity=Severity.MEDIUM,
                status=Status.PASS, details="No flows configured",
                description="Flows not updated in >180 days may contain stale credentials or outdated logic.",
                remediation="N/A", evidence=[],
            )
            return

        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=180)
        stale = []
        for f in flows:
            updated = f.get("updated_at")
            if updated:
                try:
                    dt = datetime.fromisoformat(updated)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if dt < threshold:
                        stale.append(f)
                except (ValueError, TypeError):
                    pass

        if not stale:
            status = Status.PASS
            details = f"All {len(flows)} flows updated within 180 days"
        elif len(stale) <= 3:
            status = Status.WARN
            details = f"{len(stale)}/{len(flows)} flows not updated in 180+ days"
        else:
            status = Status.FAIL
            details = f"{len(stale)}/{len(flows)} stale flows — potential credential and data quality risk"

        self._add(
            check_id="API-007", name="Stale Flow Detection",
            category=Category.API, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Prep flows that haven't been updated in >6 months may contain stale credentials, outdated transformations, or abandoned data pipelines.",
            remediation="Review stale flows with owners. Disable or remove unused flows. Rotate embedded credentials in active flows.",
            evidence=[f"{f['name']} (last updated: {f.get('updated_at', 'unknown')})" for f in stale[:15]],
        )

    def _check_data_driven_alerts(self) -> None:
        settings = self.data.get("site_settings", {})
        enabled = settings.get("data_alerts_enabled")

        if enabled is None:
            status = Status.WARN
            details = "Data-driven alerts setting not retrievable"
        elif enabled:
            status = Status.WARN
            details = "Data-driven alerts are enabled — alert emails contain data snapshots that may expose sensitive values"
        else:
            status = Status.PASS
            details = "Data-driven alerts are disabled"

        self._add(
            check_id="API-008", name="Data-Driven Alerts Exposure",
            category=Category.API, severity=Severity.LOW,
            status=status, details=details,
            description="Data-driven alerts send email notifications containing data values when thresholds are met. This can expose sensitive data via email.",
            remediation="If sensitive data exists, restrict alert creation to governed views only. Monitor alert subscriptions via Admin Insights.",
            evidence=[],
        )

    def _check_ask_data_mode(self) -> None:
        settings = self.data.get("site_settings", {})
        mode = settings.get("ask_data_mode")

        if mode is None:
            status = Status.WARN
            details = "Ask Data mode setting not retrievable"
        elif mode == "EnabledByDefault":
            status = Status.WARN
            details = "Ask Data (natural language queries) is enabled by default — users can query data sources conversationally"
        elif mode == "DisabledByDefault":
            status = Status.PASS
            details = "Ask Data is disabled by default (can be enabled per data source)"
        else:
            status = Status.PASS
            details = f"Ask Data mode: {mode}"

        self._add(
            check_id="API-009", name="Ask Data / Natural Language Mode",
            category=Category.API, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Ask Data lets users query data sources via natural language. This can bypass carefully designed dashboard-level filters and RLS if the underlying data source is not properly secured.",
            remediation="Disable Ask Data by default. Enable selectively on certified, RLS-protected data sources only. Review which data sources expose Ask Data.",
            evidence=[],
        )
