"""Identity & Authentication checks (AUTH-001 through AUTH-009)."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ..models import Finding, Status, Severity, Category
from .base import BaseChecks


class IdentityChecks(BaseChecks):
    """9 checks covering IdP federation, stale accounts, admin sprawl, auth consistency, domains, roles, and service accounts."""

    def run(self) -> list[Finding]:
        self._check_idp_federation()
        self._check_stale_accounts()
        self._check_admin_count()
        self._check_unlicensed_users()
        self._check_duplicate_admins()
        self._check_auth_setting_consistency()
        self._check_external_domain_users()
        self._check_site_role_distribution()
        self._check_service_accounts()
        return self.findings

    def _check_idp_federation(self) -> None:
        users = self.data.get("users", [])
        local_users = [u for u in users if u.get("auth_setting") in (None, "ServerDefault", "TableauIDWithMFA")]
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

    def _check_stale_accounts(self) -> None:
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
                except (ValueError, TypeError):
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

    def _check_admin_count(self) -> None:
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

    def _check_unlicensed_users(self) -> None:
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

    def _check_duplicate_admins(self) -> None:
        users = self.data.get("users", [])
        admins = [u for u in users if "Admin" in (u.get("site_role") or "")]
        names: dict[str, dict] = {}
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

    def _check_auth_setting_consistency(self) -> None:
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

    def _check_external_domain_users(self) -> None:
        users = self.data.get("users", [])
        domains: dict[str, list[dict]] = {}
        for u in users:
            dom = (u.get("domain_name") or "local").lower().strip()
            domains.setdefault(dom, []).append(u)

        # Primary domain = most common non-local domain
        non_local = {d: us for d, us in domains.items() if d != "local"}
        if not non_local:
            primary = "local"
        else:
            primary = max(non_local, key=lambda d: len(non_local[d]))

        external = [u for d, us in domains.items() if d != primary for u in us]

        if not external:
            status = Status.PASS
            details = f"All users belong to primary domain ({primary})"
        elif len(external) <= 3:
            status = Status.WARN
            details = f"{len(external)} users from external/non-primary domains"
        else:
            status = Status.FAIL
            details = f"{len(external)} users from external domains — review for unauthorized cross-org access"

        self._add(
            check_id="AUTH-007", name="External / Cross-Domain Users",
            category=Category.IDENTITY, severity=Severity.MEDIUM,
            status=status, details=details,
            description="Users from external or non-primary domains may be partners, contractors, or misconfigured accounts that require additional scrutiny.",
            remediation="Audit external-domain users. Ensure they have appropriate roles and are managed via a formal guest-access process.",
            evidence=[f"{u['name']} (domain: {u.get('domain_name', 'local')})" for u in external[:15]],
        )

    def _check_site_role_distribution(self) -> None:
        users = self.data.get("users", [])
        if not users:
            self._add(
                check_id="AUTH-008", name="Site Role Distribution Health",
                category=Category.IDENTITY, severity=Severity.MEDIUM,
                status=Status.SKIP, details="No users found",
                description="A healthy role distribution follows least privilege.",
                remediation="N/A", evidence=[],
            )
            return

        high_priv_roles = {"SiteAdministratorCreator", "SiteAdministratorExplorer", "Creator"}
        high_priv = [u for u in users if u.get("site_role") in high_priv_roles]
        ratio = len(high_priv) / len(users)

        if ratio <= 0.20:
            status = Status.PASS
            details = f"{len(high_priv)}/{len(users)} users ({ratio:.0%}) have elevated roles — healthy distribution"
        elif ratio <= 0.40:
            status = Status.WARN
            details = f"{len(high_priv)}/{len(users)} users ({ratio:.0%}) have elevated roles — review necessity"
        else:
            status = Status.FAIL
            details = f"{len(high_priv)}/{len(users)} users ({ratio:.0%}) have elevated roles — privilege creep detected"

        role_counts: dict[str, int] = {}
        for u in users:
            r = u.get("site_role", "Unknown")
            role_counts[r] = role_counts.get(r, 0) + 1

        self._add(
            check_id="AUTH-008", name="Site Role Distribution Health",
            category=Category.IDENTITY, severity=Severity.MEDIUM,
            status=status, details=details,
            description="A healthy site should follow least privilege: most users as Viewers/Explorers, few Creators, minimal Admins.",
            remediation="Review users with Creator or Admin roles. Downgrade to Explorer/Viewer where publishing is not required.",
            evidence=[f"{role}: {count}" for role, count in sorted(role_counts.items(), key=lambda x: -x[1])],
        )

    def _check_service_accounts(self) -> None:
        users = self.data.get("users", [])
        svc_patterns = ["svc_", "svc-", "service", "api_", "api-", "bot_", "bot-", "automation", "system"]
        service_accts = []
        for u in users:
            name_lower = (u.get("name") or "").lower()
            fullname_lower = (u.get("fullname") or "").lower()
            for pat in svc_patterns:
                if pat in name_lower or pat in fullname_lower:
                    service_accts.append(u)
                    break

        local_svc = [u for u in service_accts if u.get("auth_setting") in (None, "ServerDefault")]
        admin_svc = [u for u in service_accts if "Admin" in (u.get("site_role") or "")]

        if not service_accts:
            status = Status.PASS
            details = "No service account naming patterns detected"
        elif admin_svc:
            status = Status.FAIL
            details = f"{len(service_accts)} service accounts detected, {len(admin_svc)} with admin roles"
        elif local_svc:
            status = Status.WARN
            details = f"{len(service_accts)} service accounts detected, {len(local_svc)} using local auth instead of PAT/IdP"
        else:
            status = Status.PASS
            details = f"{len(service_accts)} service accounts detected — properly configured"

        self._add(
            check_id="AUTH-009", name="Service Account Detection",
            category=Category.IDENTITY, severity=Severity.HIGH,
            status=status, details=details,
            description="Service accounts should have minimal roles, use PAT-based auth, and be inventoried separately from human users.",
            remediation="Audit accounts matching service patterns. Ensure minimal site roles. Use dedicated PATs. Document ownership and purpose.",
            evidence=[f"{u['name']} (role: {u['site_role']}, auth: {u.get('auth_setting', 'default')})" for u in service_accts[:15]],
        )
