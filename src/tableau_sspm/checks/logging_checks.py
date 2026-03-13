"""Logging & Monitoring checks (LOG-001 through LOG-009)."""

from __future__ import annotations

from ..models import Finding, Status, Severity, Category
from .base import BaseChecks


class LoggingChecks(BaseChecks):
    """9 checks covering catalog, visibility, commenting, access reviews, orphaned content, request access, admin mode, ownership, and site state."""

    def run(self) -> list[Finding]:
        self._check_catalog_enabled()
        self._check_user_visibility()
        self._check_commenting_controls()
        self._check_access_review_readiness()
        self._check_orphaned_content()
        self._check_request_access()
        self._check_admin_mode()
        self._check_content_ownership_distribution()
        self._check_site_state()
        return self.findings

    def _check_catalog_enabled(self) -> None:
        settings = self.data.get("site_settings", {})
        catalog = settings.get("catalog_enabled")

        if catalog is None:
            status = Status.WARN
            details = "Catalog setting not retrievable — verify Data Management is enabled"
        elif catalog:
            status = Status.PASS
            details = "Tableau Catalog is enabled — data lineage and classification available"
        else:
            status = Status.FAIL
            details = "Tableau Catalog is DISABLED — no data lineage or classification capabilities"

        self._add(
            check_id="LOG-001", name="Tableau Catalog (Data Management)",
            category=Category.LOGGING, severity=Severity.HIGH,
            status=status, details=details,
            description="Tableau Catalog provides data lineage, impact analysis, and data quality warnings critical for security governance.",
            remediation="Enable Data Management add-on. Use Catalog to label sensitive data, track lineage, and set data quality warnings.",
            evidence=[],
        )

    def _check_user_visibility(self) -> None:
        settings = self.data.get("site_settings", {})
        visibility = settings.get("user_visibility")

        if visibility is None:
            status = Status.WARN
            details = "User visibility setting not retrievable"
        elif visibility == "FULL":
            status = Status.WARN
            details = "Full user visibility — all users can see all other users on the site"
        else:
            status = Status.PASS
            details = f"User visibility: {visibility}"

        self._add(
            check_id="LOG-002", name="User Visibility Controls",
            category=Category.LOGGING, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Full user visibility lets all users see all other site members, which may leak organizational structure.",
            remediation="Set user visibility to 'Limited' if users should only see members of groups they belong to.",
            evidence=[],
        )

    def _check_commenting_controls(self) -> None:
        settings = self.data.get("site_settings", {})
        commenting = settings.get("commenting_enabled")
        mentions = settings.get("commenting_mentions_enabled")

        if commenting is None:
            status = Status.WARN
            details = "Commenting settings not retrievable"
        elif commenting and mentions:
            status = Status.WARN
            details = "Comments and @mentions are enabled — potential data leakage via comments"
        elif commenting:
            status = Status.PASS
            details = "Commenting enabled, mentions disabled"
        else:
            status = Status.PASS
            details = "Commenting is disabled"

        self._add(
            check_id="LOG-003", name="Commenting & Mention Controls",
            category=Category.LOGGING, severity=Severity.LOW,
            status=status, details=details,
            description="Comments on views may inadvertently expose sensitive context. @mentions trigger email notifications with content previews.",
            remediation="If data sensitivity is high, consider disabling comments or mentions. Monitor comment activity via Activity Log.",
            evidence=[],
        )

    def _check_access_review_readiness(self) -> None:
        users = self.data.get("users", [])
        groups = self.data.get("groups", [])
        projects = self.data.get("projects", [])

        has_groups = len([g for g in groups if g["name"].lower() != "all users"]) > 0
        has_projects = len(projects) > 1

        if has_groups and has_projects:
            status = Status.PASS
            details = "Environment supports structured access reviews (groups + projects exist)"
        elif has_projects:
            status = Status.WARN
            details = "Project structure exists but no custom groups — access reviews will be difficult"
        else:
            status = Status.FAIL
            details = "Flat structure with no groups or project hierarchy — access review not feasible"

        self._add(
            check_id="LOG-004", name="Access Review Readiness",
            category=Category.LOGGING, severity=Severity.HIGH,
            status=status, details=details,
            description="Periodic access reviews require a structured environment with groups and project hierarchy.",
            remediation="Implement group-based access. Create project hierarchy. Schedule quarterly access reviews with data owners.",
            evidence=[f"Users: {len(users)}, Groups: {len(groups)}, Projects: {len(projects)}"],
        )

    def _check_orphaned_content(self) -> None:
        users = self.data.get("users", [])
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])
        user_ids = {u["id"] for u in users}

        orphan_wb = [w for w in workbooks if w.get("owner_id") not in user_ids]
        orphan_ds = [d for d in datasources if d.get("owner_id") not in user_ids]
        total_orphaned = len(orphan_wb) + len(orphan_ds)

        if total_orphaned == 0:
            status = Status.PASS
            details = "No orphaned content detected"
        else:
            status = Status.WARN
            details = f"{total_orphaned} content items owned by users no longer on the site"

        self._add(
            check_id="LOG-005", name="Orphaned Content Detection",
            category=Category.LOGGING, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Content owned by departed users lacks an active steward for security governance and access reviews.",
            remediation="Reassign orphaned content to active owners. Implement a content ownership transfer process for offboarding.",
            evidence=[f"Orphaned workbooks: {len(orphan_wb)}, Orphaned data sources: {len(orphan_ds)}"],
        )

    def _check_request_access(self) -> None:
        settings = self.data.get("site_settings", {})
        enabled = settings.get("request_access_enabled")

        if enabled is None:
            status = Status.WARN
            details = "Request access setting not retrievable"
        elif enabled:
            status = Status.PASS
            details = "Request access is enabled — users can request permissions through governed workflow"
        else:
            status = Status.WARN
            details = "Request access is disabled — users may resort to ad-hoc permission grants"

        self._add(
            check_id="LOG-006", name="Governed Access Request Workflow",
            category=Category.LOGGING, severity=Severity.LOW,
            status=status, details=details,
            description="A governed access request workflow helps maintain audit trails for permission changes.",
            remediation="Enable request access so permission requests go to content owners. Combine with external approval workflows if needed.",
            evidence=[],
        )

    def _check_admin_mode(self) -> None:
        settings = self.data.get("site_settings", {})
        mode = settings.get("admin_mode")

        if mode is None:
            status = Status.WARN
            details = "Admin mode setting not retrievable"
        elif mode == "ContentOnly":
            status = Status.PASS
            details = "Site admin mode is ContentOnly — admins cannot manage users directly"
        elif mode == "ContentAndUsers":
            status = Status.WARN
            details = "Site admin mode is ContentAndUsers — site admins can manage both content and user accounts"
        else:
            status = Status.WARN
            details = f"Admin mode: {mode} — verify appropriateness"

        self._add(
            check_id="LOG-007", name="Admin Mode Configuration",
            category=Category.LOGGING, severity=Severity.MEDIUM,
            status=status, details=details,
            description="ContentAndUsers mode gives site admins full control including user provisioning. ContentOnly restricts admins to content management, with users managed via IdP/SCIM.",
            remediation="If using SCIM/IdP for user provisioning, set admin mode to ContentOnly. This reduces admin blast radius and enforces centralized identity management.",
            evidence=[],
        )

    def _check_content_ownership_distribution(self) -> None:
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])
        users = self.data.get("users", [])

        all_content = workbooks + datasources
        if not all_content:
            self._add(
                check_id="LOG-008", name="Content Ownership Distribution",
                category=Category.LOGGING, severity=Severity.MEDIUM,
                status=Status.SKIP, details="No content found",
                description="Well-distributed content ownership enables effective monitoring and access reviews.",
                remediation="N/A", evidence=[],
            )
            return

        owner_counts: dict[str, int] = {}
        for item in all_content:
            oid = item.get("owner_id", "unknown")
            owner_counts[oid] = owner_counts.get(oid, 0) + 1

        user_map = {u["id"]: u["name"] for u in users}
        unique_owners = len(owner_counts)
        total_users = len(users)

        if unique_owners == 0:
            ownership_ratio = 0.0
        else:
            ownership_ratio = unique_owners / max(total_users, 1)

        if ownership_ratio >= 0.20:
            status = Status.PASS
            details = f"{unique_owners} distinct content owners across {total_users} users — healthy distribution for monitoring"
        elif ownership_ratio >= 0.10:
            status = Status.WARN
            details = f"Only {unique_owners} content owners out of {total_users} users ({ownership_ratio:.0%}) — monitoring concentrated on few accounts"
        else:
            status = Status.FAIL
            details = f"Only {unique_owners} content owners — insufficient distribution for effective monitoring"

        top_owners = sorted(owner_counts.items(), key=lambda x: -x[1])[:5]
        self._add(
            check_id="LOG-008", name="Content Ownership Distribution",
            category=Category.LOGGING, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Concentrated content ownership means monitoring and access reviews depend on very few individuals. This creates blind spots.",
            remediation="Distribute ownership across team leads. Assign content stewards per department. Use Admin Insights to identify ownership gaps.",
            evidence=[f"{user_map.get(oid, oid)}: {count} items" for oid, count in top_owners],
        )

    def _check_site_state(self) -> None:
        settings = self.data.get("site_settings", {})
        state = settings.get("state")

        if state is None:
            status = Status.WARN
            details = "Site state not retrievable"
        elif state == "Active":
            status = Status.PASS
            details = "Site is Active"
        elif state == "Suspended":
            status = Status.FAIL
            details = "Site is SUSPENDED — all access is blocked, investigate immediately"
        else:
            status = Status.WARN
            details = f"Site state: {state} — verify expected"

        self._add(
            check_id="LOG-009", name="Site Activation State",
            category=Category.LOGGING, severity=Severity.HIGH,
            status=status, details=details,
            description="A suspended or non-Active site state indicates a potential licensing, billing, or administrative issue that blocks all users.",
            remediation="If suspended, contact Tableau/Salesforce support. Verify site state is Active. Set up monitoring alerts for state changes.",
            evidence=[],
        )
