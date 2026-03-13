"""Access Control & Permissions checks (ACCS-001 through ACCS-009)."""

from __future__ import annotations

from ..models import Finding, Status, Severity, Category
from .base import BaseChecks


class AccessControlChecks(BaseChecks):
    """9 checks covering over-privileged users, project permissions, guest access, groups, derived perms, hierarchy, and ownership."""

    def run(self) -> list[Finding]:
        self._check_overprivileged_users()
        self._check_default_project_permissions()
        self._check_locked_permissions()
        self._check_guest_access()
        self._check_group_based_access()
        self._check_all_users_group_abuse()
        self._check_derived_permissions()
        self._check_project_hierarchy_depth()
        self._check_single_owner_concentration()
        return self.findings

    def _check_overprivileged_users(self) -> None:
        users = self.data.get("users", [])
        creators = [u for u in users if u.get("site_role") in ("Creator", "SiteAdministratorCreator")]
        idle_creators = [u for u in creators if u.get("workbook_count", 0) == 0
                         and u.get("site_role") == "Creator"]

        if not idle_creators:
            status = Status.PASS
            details = "All Creator-licensed users have published content"
        elif len(idle_creators) <= 2:
            status = Status.WARN
            details = f"{len(idle_creators)} Creator-licensed users with no published workbooks"
        else:
            status = Status.FAIL
            details = f"{len(idle_creators)} Creator-licensed users have published zero workbooks — likely over-provisioned"

        self._add(
            check_id="ACCS-001", name="Over-Privileged Creator Accounts",
            category=Category.ACCESS, severity=Severity.HIGH,
            status=status, details=details,
            description="Users with Creator licenses who don't publish content should be downgraded to Explorer or Viewer.",
            remediation="Audit Creator-role users against Admin Insights usage data. Downgrade inactive creators to Explorer. Save license costs.",
            evidence=[f"{u['name']} (Creator, 0 workbooks)" for u in idle_creators[:15]],
        )

    def _check_default_project_permissions(self) -> None:
        projects = self.data.get("projects", [])
        default_projects = [p for p in projects if p["name"].lower() == "default"]

        if not default_projects:
            status = Status.PASS
            details = "No 'Default' project found — custom project structure in use"
        else:
            perm_mode = default_projects[0].get("content_permissions", "Unknown")
            if perm_mode in ("ManagedByOwner", "LockedToProject"):
                status = Status.WARN
                details = f"Default project exists with permission mode: {perm_mode} — verify All Users group is removed"
            else:
                status = Status.WARN
                details = f"Default project exists (mode: {perm_mode}) — verify restrictive permissions"

        self._add(
            check_id="ACCS-002", name="Default Project Permissions",
            category=Category.ACCESS, severity=Severity.HIGH,
            status=status, details=details,
            description="The Default project should have restrictive permissions. Open defaults give all users access to ungoverned content.",
            remediation="Remove 'All Users' from Default project. Set content permissions to 'Locked'. Create governed project hierarchy.",
            evidence=[f"Project: {p['name']} (mode: {p.get('content_permissions', 'N/A')})" for p in default_projects],
        )

    def _check_locked_permissions(self) -> None:
        projects = self.data.get("projects", [])
        unlocked = [p for p in projects if p.get("content_permissions") not in ("LockedToProject", "LockedToProjectWithoutNested")]
        total = len(projects)
        unlocked_count = len(unlocked)

        if total == 0:
            status = Status.SKIP
            details = "No projects found"
        elif unlocked_count == 0:
            status = Status.PASS
            details = f"All {total} projects use locked permissions"
        elif unlocked_count <= total * 0.3:
            status = Status.WARN
            details = f"{unlocked_count}/{total} projects have unlocked permissions"
        else:
            status = Status.FAIL
            details = f"{unlocked_count}/{total} projects allow content owners to override permissions"

        self._add(
            check_id="ACCS-003", name="Project Permission Locking",
            category=Category.ACCESS, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Unlocked projects let content owners override project-level permissions, breaking governance controls.",
            remediation="Set projects to 'Locked to project' to enforce top-down permission governance. Especially lock projects with sensitive data.",
            evidence=[f"{p['name']} ({p.get('content_permissions', 'N/A')})" for p in unlocked[:15]],
        )

    def _check_guest_access(self) -> None:
        settings = self.data.get("site_settings", {})
        guest = settings.get("guest_access_enabled")

        if guest is None:
            status = Status.WARN
            details = "Unable to determine guest access setting — verify manually"
        elif guest:
            status = Status.FAIL
            details = "Guest (unauthenticated) access is ENABLED"
        else:
            status = Status.PASS
            details = "Guest access is disabled"

        self._add(
            check_id="ACCS-004", name="Guest User Access",
            category=Category.ACCESS, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Guest access allows unauthenticated viewing of content. Should only be enabled for specific embedded analytics use cases.",
            remediation="Disable guest access in Site Settings unless required for embedded views. If required, restrict to specific projects.",
            evidence=[],
        )

    def _check_group_based_access(self) -> None:
        groups = self.data.get("groups", [])
        custom_groups = [g for g in groups if g["name"].lower() != "all users"]

        if len(custom_groups) >= 3:
            status = Status.PASS
            details = f"{len(custom_groups)} custom groups configured for access control"
        elif len(custom_groups) >= 1:
            status = Status.WARN
            details = f"Only {len(custom_groups)} custom groups — consider more granular group structure"
        else:
            status = Status.FAIL
            details = "No custom groups found — permissions likely assigned to individual users"

        self._add(
            check_id="ACCS-005", name="Group-Based Access Control",
            category=Category.ACCESS, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Permissions should be managed via groups (ideally IdP-synced) rather than individual user assignments.",
            remediation="Create groups mapped to teams/roles. Sync from IdP via SCIM. Migrate individual permissions to group-based.",
            evidence=[f"{g['name']} ({g.get('user_count', '?')} members)" for g in custom_groups[:15]],
        )

    def _check_all_users_group_abuse(self) -> None:
        groups = self.data.get("groups", [])
        all_users = [g for g in groups if g["name"].lower() == "all users"]
        users = self.data.get("users", [])

        if not all_users:
            status = Status.PASS
            details = "All Users group not prominent"
        else:
            count = all_users[0].get("user_count", len(users))
            status = Status.WARN
            details = f"All Users group contains {count} members — verify it's not used for project/datasource permissions"

        self._add(
            check_id="ACCS-006", name="'All Users' Group Permission Scope",
            category=Category.ACCESS, severity=Severity.HIGH,
            status=status, details=details,
            description="Granting permissions to the 'All Users' group effectively makes content accessible to every site member.",
            remediation="Audit projects and data sources for 'All Users' group permissions. Replace with specific role-based groups.",
            evidence=[],
        )

    def _check_derived_permissions(self) -> None:
        settings = self.data.get("site_settings", {})
        derived = settings.get("derived_permissions_enabled")

        if derived is None:
            status = Status.WARN
            details = "Derived permissions setting not retrievable"
        elif derived:
            status = Status.WARN
            details = "Derived permissions are ENABLED — permissions cascade from projects to nested content automatically"
        else:
            status = Status.PASS
            details = "Derived permissions are disabled — explicit permission grants required"

        self._add(
            check_id="ACCS-007", name="Derived Permissions Enabled",
            category=Category.ACCESS, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Derived permissions automatically propagate project-level access to nested content. This can unintentionally grant broader access than intended.",
            remediation="Evaluate whether derived permissions align with your governance model. For sensitive projects, disable derived permissions and grant access explicitly.",
            evidence=[],
        )

    def _check_project_hierarchy_depth(self) -> None:
        projects = self.data.get("projects", [])
        if not projects:
            self._add(
                check_id="ACCS-008", name="Project Hierarchy Depth",
                category=Category.ACCESS, severity=Severity.LOW,
                status=Status.SKIP, details="No projects found",
                description="A nested project hierarchy enables fine-grained governance.",
                remediation="N/A", evidence=[],
            )
            return

        top_level = [p for p in projects if p.get("parent_id") is None]
        nested = [p for p in projects if p.get("parent_id") is not None]

        if nested:
            status = Status.PASS
            details = f"{len(top_level)} top-level, {len(nested)} nested projects — hierarchy supports governance"
        elif len(top_level) >= 3:
            status = Status.WARN
            details = f"All {len(top_level)} projects are top-level (flat structure) — limited governance granularity"
        else:
            status = Status.PASS
            details = f"{len(top_level)} projects — small site, flat structure acceptable"

        self._add(
            check_id="ACCS-008", name="Project Hierarchy Depth",
            category=Category.ACCESS, severity=Severity.LOW,
            status=status, details=details,
            description="Nested project hierarchies enable department-level governance with inherited permissions and clearer content organization.",
            remediation="Create a multi-tier project hierarchy (e.g., Department → Team → Use Case). Use nested projects for permission inheritance.",
            evidence=[f"{p['name']} (parent: {p.get('parent_id', 'root')})" for p in projects[:15]],
        )

    def _check_single_owner_concentration(self) -> None:
        projects = self.data.get("projects", [])
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])

        all_items = projects + workbooks + datasources
        if not all_items:
            self._add(
                check_id="ACCS-009", name="Single-Owner Content Concentration",
                category=Category.ACCESS, severity=Severity.MEDIUM,
                status=Status.SKIP, details="No content found",
                description="Content concentrated under a single owner creates governance and bus-factor risk.",
                remediation="N/A", evidence=[],
            )
            return

        owner_counts: dict[str, int] = {}
        for item in all_items:
            oid = item.get("owner_id", "unknown")
            owner_counts[oid] = owner_counts.get(oid, 0) + 1

        top_owner = max(owner_counts, key=lambda o: owner_counts[o])
        top_count = owner_counts[top_owner]
        total = len(all_items)
        concentration = top_count / total

        users = self.data.get("users", [])
        owner_name = next((u["name"] for u in users if u["id"] == top_owner), top_owner)

        if concentration <= 0.40:
            status = Status.PASS
            details = f"Content ownership is distributed (top owner: {concentration:.0%} of {total} items)"
        elif concentration <= 0.70:
            status = Status.WARN
            details = f"{owner_name} owns {top_count}/{total} items ({concentration:.0%}) — moderate concentration"
        else:
            status = Status.FAIL
            details = f"{owner_name} owns {top_count}/{total} items ({concentration:.0%}) — high bus-factor risk"

        self._add(
            check_id="ACCS-009", name="Single-Owner Content Concentration",
            category=Category.ACCESS, severity=Severity.MEDIUM,
            status=status, details=details,
            description="When most content is owned by one user, that person's departure or account compromise has outsized impact.",
            remediation="Distribute content ownership across team leads. Transfer project ownership to functional accounts or team leads.",
            evidence=[f"{owner}: {count} items" for owner, count in sorted(owner_counts.items(), key=lambda x: -x[1])[:10]],
        )
