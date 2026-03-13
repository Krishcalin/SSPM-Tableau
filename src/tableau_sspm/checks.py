"""Security control checks.

Evaluates collected Tableau Cloud configuration data against
30 security controls across 5 domains.
"""

from datetime import datetime, timezone, timedelta
from .models import Finding, Status, Severity, Category


# ── Security Checks ───────────────────────────────────────────────

class SecurityChecks:
    """Evaluates collected data against security controls."""

    def __init__(self, data: dict):
        self.data = data
        self.findings: list[Finding] = []

    def run_all(self):
        print("  ├─ Running identity checks...")
        self._check_idp_federation()
        self._check_stale_accounts()
        self._check_admin_count()
        self._check_unlicensed_users()
        self._check_duplicate_admins()
        self._check_auth_setting_consistency()

        print("  ├─ Running access control checks...")
        self._check_overprivileged_users()
        self._check_default_project_permissions()
        self._check_locked_permissions()
        self._check_guest_access()
        self._check_group_based_access()
        self._check_all_users_group_abuse()

        print("  ├─ Running data security checks...")
        self._check_embedded_credentials()
        self._check_extract_encryption()
        self._check_sensitive_datasource_names()
        self._check_datasource_certification()
        self._check_data_download_surface()
        self._check_stale_datasources()

        print("  ├─ Running API & integration checks...")
        self._check_extension_surface()
        self._check_revision_history()
        self._check_subscribe_others()
        self._check_run_now_enabled()
        self._check_flow_security()
        self._check_content_sprawl()

        print("  ├─ Running logging & monitoring checks...")
        self._check_catalog_enabled()
        self._check_user_visibility()
        self._check_commenting_controls()
        self._check_access_review_readiness()
        self._check_orphaned_content()
        self._check_request_access()

        print(f"  └─ {len(self.findings)} checks completed\n")
        return self.findings

    def _add(self, **kwargs):
        self.findings.append(Finding(**kwargs))

    # ── Identity & Authentication ──────────────────────────────

    def _check_idp_federation(self):
        users = self.data.get("users", [])
        local_users = [u for u in users if u.get("auth_setting") in (None, "ServerDefault", "TableauIDWithMFA")]
        saml_users = [u for u in users if u.get("auth_setting") in ("SAML",)]
        total = len(users)
        local_count = len(local_users)

        if total == 0:
            status = Status.SKIP
            details = "No users found"
        elif local_count == 0:
            status = Status.PASS
            details = f"All {total} users authenticate via IdP"
        elif local_count <= 2:
            status = Status.WARN
            details = f"{local_count}/{total} users on local auth (likely break-glass accounts)"
        else:
            status = Status.FAIL
            details = f"{local_count}/{total} users not using IdP federation"

        self._add(
            check_id="AUTH-001", name="IdP Federation (SAML/OIDC)",
            category=Category.IDENTITY, severity=Severity.CRITICAL,
            status=status, details=details,
            description="All users should authenticate via an external IdP. Local/TableauID auth increases credential risk.",
            remediation="Configure SAML or OIDC in Settings → Authentication. Keep at most 1-2 break-glass admin accounts on local auth.",
            evidence=[f"{u['name']} ({u.get('auth_setting', 'default')})" for u in local_users[:20]],
        )

    def _check_stale_accounts(self):
        users = self.data.get("users", [])
        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=90)
        stale = []
        never_logged_in = []

        for u in users:
            if u["last_login"] is None:
                never_logged_in.append(u)
            else:
                try:
                    last = datetime.fromisoformat(u["last_login"])
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    if last < threshold:
                        stale.append(u)
                except Exception:
                    pass

        total_inactive = len(stale) + len(never_logged_in)
        if total_inactive == 0:
            status = Status.PASS
            details = "No stale or never-logged-in accounts found"
        elif total_inactive <= 3:
            status = Status.WARN
            details = f"{total_inactive} inactive accounts ({len(stale)} stale, {len(never_logged_in)} never logged in)"
        else:
            status = Status.FAIL
            details = f"{total_inactive} inactive accounts ({len(stale)} stale >90d, {len(never_logged_in)} never logged in)"

        evidence = [f"{u['name']} – last login: {u['last_login'] or 'never'}" for u in (stale + never_logged_in)[:25]]
        self._add(
            check_id="AUTH-002", name="Stale Account Detection (>90 days)",
            category=Category.IDENTITY, severity=Severity.HIGH,
            status=status, details=details,
            description="Accounts inactive for >90 days or that have never logged in expand attack surface and should be deprovisioned.",
            remediation="Remove or disable accounts inactive >90 days. Enable SCIM auto-deprovisioning from your IdP. Audit quarterly.",
            evidence=evidence,
        )

    def _check_admin_count(self):
        users = self.data.get("users", [])
        admins = [u for u in users if "Admin" in (u.get("site_role") or "")]
        site_admins = [u for u in admins if u.get("site_role") == "SiteAdministratorCreator"]
        explorer_admins = [u for u in admins if u.get("site_role") == "SiteAdministratorExplorer"]

        count = len(admins)
        if count <= 3:
            status = Status.PASS
            details = f"{count} admin accounts (within recommended threshold of ≤3)"
        elif count <= 5:
            status = Status.WARN
            details = f"{count} admin accounts ({len(site_admins)} Creator, {len(explorer_admins)} Explorer) — consider reducing"
        else:
            status = Status.FAIL
            details = f"{count} admin accounts detected — excessive admin sprawl"

        self._add(
            check_id="AUTH-003", name="Site Administrator Count",
            category=Category.IDENTITY, severity=Severity.HIGH,
            status=status, details=details,
            description="Excessive site admin accounts violate least privilege and increase the blast radius of credential compromise.",
            remediation="Reduce to ≤3 site admins. Convert unnecessary admins to Explorer or Creator roles. Document admin justification.",
            evidence=[f"{u['name']} ({u['site_role']})" for u in admins],
        )

    def _check_unlicensed_users(self):
        users = self.data.get("users", [])
        unlicensed = [u for u in users if u.get("site_role") in ("Unlicensed", "Viewer")]
        never_viewed = [u for u in unlicensed if u.get("last_login") is None]

        if len(never_viewed) == 0:
            status = Status.PASS
            details = "No unlicensed users with zero activity found"
        else:
            status = Status.WARN
            details = f"{len(never_viewed)} unlicensed/viewer accounts that have never logged in"

        self._add(
            check_id="AUTH-004", name="Unlicensed / Inactive Viewer Cleanup",
            category=Category.IDENTITY, severity=Severity.LOW,
            status=status, details=details,
            description="Unlicensed users who've never logged in are likely provisioning artifacts that should be cleaned up.",
            remediation="Remove unlicensed accounts that have never logged in. Automate user lifecycle via SCIM provisioning.",
            evidence=[f"{u['name']} ({u['site_role']})" for u in never_viewed[:15]],
        )

    def _check_duplicate_admins(self):
        users = self.data.get("users", [])
        admins = [u for u in users if "Admin" in (u.get("site_role") or "")]
        # Check if any admins share a similar name pattern (possible duplicates)
        names = {}
        dupes = []
        for a in admins:
            base = (a.get("fullname") or a["name"]).lower().strip()
            if base in names:
                dupes.append(a)
            names[base] = a

        if not dupes:
            status = Status.PASS
            details = "No duplicate admin accounts detected"
        else:
            status = Status.WARN
            details = f"{len(dupes)} potential duplicate admin accounts"

        self._add(
            check_id="AUTH-005", name="Duplicate Admin Account Detection",
            category=Category.IDENTITY, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Duplicate admin accounts may indicate shared credentials or failed deprovisioning.",
            remediation="Investigate duplicate accounts. Consolidate to a single identity per person. Enforce via IdP group mapping.",
            evidence=[f"{u['name']} ({u['fullname']})" for u in dupes[:10]],
        )

    def _check_auth_setting_consistency(self):
        users = self.data.get("users", [])
        auth_types = set(u.get("auth_setting") or "default" for u in users)
        mixed = len(auth_types) > 1

        if not mixed:
            status = Status.PASS
            details = f"Consistent auth method across all users: {auth_types.pop()}"
        else:
            status = Status.WARN
            details = f"Mixed auth methods detected: {', '.join(sorted(auth_types))}"

        self._add(
            check_id="AUTH-006", name="Authentication Method Consistency",
            category=Category.IDENTITY, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Mixed authentication methods complicate security policy enforcement and monitoring.",
            remediation="Standardize on a single IdP-based auth method. Exceptions (break-glass) should be documented and monitored.",
            evidence=[],
        )

    # ── Access Control ─────────────────────────────────────────

    def _check_overprivileged_users(self):
        users = self.data.get("users", [])
        creators = [u for u in users if u.get("site_role") in ("Creator", "SiteAdministratorCreator")]
        # Creators who own zero workbooks may be over-provisioned
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

    def _check_default_project_permissions(self):
        projects = self.data.get("projects", [])
        default_projects = [p for p in projects if p["name"].lower() == "default"]

        if not default_projects:
            status = Status.PASS
            details = "No 'Default' project found — custom project structure in use"
        else:
            # Can't directly check permission rules via TSC easily,
            # so flag the existence of Default as needing manual review
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

    def _check_locked_permissions(self):
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

    def _check_guest_access(self):
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

    def _check_group_based_access(self):
        groups = self.data.get("groups", [])
        users = self.data.get("users", [])
        # Check if meaningful groups exist (beyond 'All Users')
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

    def _check_all_users_group_abuse(self):
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

    # ── Data Security ──────────────────────────────────────────

    def _check_embedded_credentials(self):
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

    def _check_extract_encryption(self):
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

    def _check_sensitive_datasource_names(self):
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

    def _check_datasource_certification(self):
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

    def _check_data_download_surface(self):
        workbooks = self.data.get("workbooks", [])
        datasources = self.data.get("datasources", [])
        total_content = len(workbooks) + len(datasources)

        # We can't check download permissions directly via REST easily,
        # so flag this as needing review proportional to content volume
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

    def _check_stale_datasources(self):
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
                except Exception:
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

    # ── API & Integrations ─────────────────────────────────────

    def _check_extension_surface(self):
        # REST API doesn't directly expose extension allowlist,
        # so we flag based on site having content that could use extensions
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

    def _check_revision_history(self):
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

    def _check_subscribe_others(self):
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

    def _check_run_now_enabled(self):
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

    def _check_flow_security(self):
        flows = self.data.get("flows", [])
        settings = self.data.get("site_settings", {})
        flows_enabled = settings.get("flows_enabled")

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

    def _check_content_sprawl(self):
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

    # ── Logging & Monitoring ───────────────────────────────────

    def _check_catalog_enabled(self):
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

    def _check_user_visibility(self):
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

    def _check_commenting_controls(self):
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

    def _check_access_review_readiness(self):
        users = self.data.get("users", [])
        groups = self.data.get("groups", [])
        projects = self.data.get("projects", [])

        # Assess whether the environment has enough metadata for meaningful access reviews
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

    def _check_orphaned_content(self):
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

    def _check_request_access(self):
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
