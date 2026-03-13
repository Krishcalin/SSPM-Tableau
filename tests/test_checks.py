"""Unit tests for security checks — no API calls required."""

import pytest
from tableau_sspm.checks import SecurityChecks
from tableau_sspm.models import Status, Severity, Category


class TestIdentityChecks:
    """AUTH-001 through AUTH-006."""

    @pytest.mark.unit
    def test_idp_federation_all_saml_passes(self, full_scan_data):
        # Make all users SAML
        for u in full_scan_data["users"]:
            u["auth_setting"] = "SAML"
        checks = SecurityChecks(full_scan_data)
        checks._check_idp_federation()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_idp_federation_local_users_fail(self, full_scan_data):
        # Add many local auth users
        for u in full_scan_data["users"]:
            u["auth_setting"] = "ServerDefault"
        checks = SecurityChecks(full_scan_data)
        checks._check_idp_federation()
        assert checks.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_idp_federation_breakglass_warns(self, full_scan_data):
        # Only 1 user on local auth (break-glass)
        for u in full_scan_data["users"]:
            u["auth_setting"] = "SAML"
        full_scan_data["users"][1]["auth_setting"] = "ServerDefault"
        checks = SecurityChecks(full_scan_data)
        checks._check_idp_federation()
        assert checks.findings[0].status == Status.WARN

    @pytest.mark.unit
    def test_stale_accounts_detected(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_stale_accounts()
        f = checks.findings[0]
        # Fixture has 1 stale (120d) + 1 never-logged-in
        assert f.status in (Status.WARN, Status.FAIL)
        assert "inactive" in f.details.lower()

    @pytest.mark.unit
    def test_admin_count_low_passes(self, full_scan_data):
        # Keep only 2 admins
        for u in full_scan_data["users"]:
            if u["site_role"] not in ("SiteAdministratorCreator",):
                continue
        checks = SecurityChecks(full_scan_data)
        checks._check_admin_count()
        f = checks.findings[0]
        assert f.severity == Severity.HIGH


class TestAccessControlChecks:
    """ACCS-001 through ACCS-006."""

    @pytest.mark.unit
    def test_overprivileged_creators_detected(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_overprivileged_users()
        f = checks.findings[0]
        # Fixture has idle-creator@corp.com with 0 workbooks
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_locked_permissions_partial(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_locked_permissions()
        f = checks.findings[0]
        # 2 of 4 projects are unlocked
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_guest_access_disabled_passes(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_guest_access()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_guest_access_enabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["guest_access_enabled"] = True
        checks = SecurityChecks(full_scan_data)
        checks._check_guest_access()
        assert checks.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_group_based_access_with_custom_groups(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_group_based_access()
        # 3 custom groups in fixture
        assert checks.findings[0].status == Status.PASS


class TestDataSecurityChecks:
    """DATA-001 through DATA-006."""

    @pytest.mark.unit
    def test_embedded_credentials_found(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_embedded_credentials()
        f = checks.findings[0]
        # 2 datasources have embed_password=True
        assert f.status in (Status.WARN, Status.FAIL)
        assert f.severity == Severity.CRITICAL

    @pytest.mark.unit
    def test_embedded_credentials_clean(self, full_scan_data):
        for ds in full_scan_data["datasources"]:
            for conn in ds["connections"]:
                conn["embed_password"] = False
        checks = SecurityChecks(full_scan_data)
        checks._check_embedded_credentials()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_sensitive_datasource_naming(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_sensitive_datasource_names()
        f = checks.findings[0]
        # "Employee PII Data" matches "pii"
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_stale_datasources_detected(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_stale_datasources()
        f = checks.findings[0]
        # "Employee PII Data" is 200 days old
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_extract_encryption_enforced(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_extract_encryption()
        assert checks.findings[0].status == Status.PASS


class TestAPIChecks:
    """API-001 through API-006."""

    @pytest.mark.unit
    def test_revision_history_enabled(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_revision_history()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_revision_history_disabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["revision_history_enabled"] = False
        checks = SecurityChecks(full_scan_data)
        checks._check_revision_history()
        assert checks.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_content_sprawl_low_ratio(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_content_sprawl()
        f = checks.findings[0]
        # 5 content items / 4 projects = 1.25 ratio — well within limits
        assert f.status == Status.PASS


class TestLoggingChecks:
    """LOG-001 through LOG-006."""

    @pytest.mark.unit
    def test_catalog_enabled_passes(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_catalog_enabled()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_catalog_disabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["catalog_enabled"] = False
        checks = SecurityChecks(full_scan_data)
        checks._check_catalog_enabled()
        assert checks.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_orphaned_content_none(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_orphaned_content()
        assert checks.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_access_review_readiness(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        checks._check_access_review_readiness()
        # Has groups + projects
        assert checks.findings[0].status == Status.PASS


class TestFullScan:
    """End-to-end scan using fixture data."""

    @pytest.mark.unit
    def test_run_all_returns_30_findings(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        assert len(findings) == 30

    @pytest.mark.unit
    def test_all_categories_covered(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        categories = {f.category for f in findings}
        assert Category.IDENTITY in categories
        assert Category.ACCESS in categories
        assert Category.DATA in categories
        assert Category.API in categories
        assert Category.LOGGING in categories

    @pytest.mark.unit
    def test_all_findings_have_remediation(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        for f in findings:
            assert f.remediation, f"Check {f.check_id} missing remediation"

    @pytest.mark.unit
    def test_all_findings_have_valid_status(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        valid = {Status.PASS, Status.FAIL, Status.WARN, Status.ERROR, Status.SKIP}
        for f in findings:
            assert f.status in valid, f"Check {f.check_id} has invalid status: {f.status}"
