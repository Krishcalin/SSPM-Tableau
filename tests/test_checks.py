"""Unit tests for security checks — no API calls required."""

import pytest
from tableau_sspm.checks import SecurityChecks
from tableau_sspm.checks.identity import IdentityChecks
from tableau_sspm.checks.access import AccessControlChecks
from tableau_sspm.checks.data import DataSecurityChecks
from tableau_sspm.checks.api import APIChecks
from tableau_sspm.checks.logging_checks import LoggingChecks
from tableau_sspm.models import Status, Severity, Category


class TestIdentityChecks:
    """AUTH-001 through AUTH-009."""

    @pytest.mark.unit
    def test_idp_federation_all_saml_passes(self, full_scan_data):
        for u in full_scan_data["users"]:
            u["auth_setting"] = "SAML"
        suite = IdentityChecks(full_scan_data)
        suite._check_idp_federation()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_idp_federation_local_users_fail(self, full_scan_data):
        for u in full_scan_data["users"]:
            u["auth_setting"] = "ServerDefault"
        suite = IdentityChecks(full_scan_data)
        suite._check_idp_federation()
        assert suite.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_idp_federation_breakglass_warns(self, full_scan_data):
        for u in full_scan_data["users"]:
            u["auth_setting"] = "SAML"
        full_scan_data["users"][1]["auth_setting"] = "ServerDefault"
        suite = IdentityChecks(full_scan_data)
        suite._check_idp_federation()
        assert suite.findings[0].status == Status.WARN

    @pytest.mark.unit
    def test_stale_accounts_detected(self, full_scan_data):
        suite = IdentityChecks(full_scan_data)
        suite._check_stale_accounts()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)
        assert "inactive" in f.details.lower()

    @pytest.mark.unit
    def test_admin_count_low_passes(self, full_scan_data):
        suite = IdentityChecks(full_scan_data)
        suite._check_admin_count()
        f = suite.findings[0]
        assert f.severity == Severity.HIGH

    @pytest.mark.unit
    def test_external_domain_users_detected(self, full_scan_data):
        # Fixture has "local" domain user (breakglass) — external to primary "corp.com"
        suite = IdentityChecks(full_scan_data)
        suite._check_external_domain_users()
        f = suite.findings[0]
        assert f.check_id == "AUTH-007"
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_external_domain_all_same_passes(self, full_scan_data):
        for u in full_scan_data["users"]:
            u["domain_name"] = "corp.com"
        suite = IdentityChecks(full_scan_data)
        suite._check_external_domain_users()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_site_role_distribution(self, full_scan_data):
        suite = IdentityChecks(full_scan_data)
        suite._check_site_role_distribution()
        f = suite.findings[0]
        assert f.check_id == "AUTH-008"
        assert f.status in (Status.PASS, Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_service_account_no_pattern_passes(self, full_scan_data):
        suite = IdentityChecks(full_scan_data)
        suite._check_service_accounts()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_service_account_admin_fails(self, full_scan_data):
        full_scan_data["users"].append({
            "id": "u-svc", "name": "svc_tableau@corp.com", "fullname": "Service Account",
            "site_role": "SiteAdministratorCreator", "auth_setting": "ServerDefault",
            "last_login": None, "domain_name": "corp.com", "workbook_count": 0,
        })
        suite = IdentityChecks(full_scan_data)
        suite._check_service_accounts()
        assert suite.findings[0].status == Status.FAIL


class TestAccessControlChecks:
    """ACCS-001 through ACCS-009."""

    @pytest.mark.unit
    def test_overprivileged_creators_detected(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_overprivileged_users()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_locked_permissions_partial(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_locked_permissions()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_guest_access_disabled_passes(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_guest_access()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_guest_access_enabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["guest_access_enabled"] = True
        suite = AccessControlChecks(full_scan_data)
        suite._check_guest_access()
        assert suite.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_group_based_access_with_custom_groups(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_group_based_access()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_derived_permissions_enabled_warns(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_derived_permissions()
        f = suite.findings[0]
        assert f.check_id == "ACCS-007"
        assert f.status == Status.WARN  # fixture has derived_permissions_enabled=True

    @pytest.mark.unit
    def test_derived_permissions_disabled_passes(self, full_scan_data):
        full_scan_data["site_settings"]["derived_permissions_enabled"] = False
        suite = AccessControlChecks(full_scan_data)
        suite._check_derived_permissions()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_project_hierarchy_flat_warns(self, full_scan_data):
        # All fixture projects have parent_id=None (flat)
        suite = AccessControlChecks(full_scan_data)
        suite._check_project_hierarchy_depth()
        f = suite.findings[0]
        assert f.check_id == "ACCS-008"
        assert f.status == Status.WARN

    @pytest.mark.unit
    def test_project_hierarchy_nested_passes(self, full_scan_data):
        full_scan_data["projects"][2]["parent_id"] = "p-001"
        suite = AccessControlChecks(full_scan_data)
        suite._check_project_hierarchy_depth()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_single_owner_concentration(self, full_scan_data):
        suite = AccessControlChecks(full_scan_data)
        suite._check_single_owner_concentration()
        f = suite.findings[0]
        assert f.check_id == "ACCS-009"
        # u-001 owns all projects, u-003 owns all workbooks/datasources
        assert f.status in (Status.WARN, Status.FAIL)


class TestDataSecurityChecks:
    """DATA-001 through DATA-009."""

    @pytest.mark.unit
    def test_embedded_credentials_found(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_embedded_credentials()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)
        assert f.severity == Severity.CRITICAL

    @pytest.mark.unit
    def test_embedded_credentials_clean(self, full_scan_data):
        for ds in full_scan_data["datasources"]:
            for conn in ds["connections"]:
                conn["embed_password"] = False
        suite = DataSecurityChecks(full_scan_data)
        suite._check_embedded_credentials()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_sensitive_datasource_naming(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_sensitive_datasource_names()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_stale_datasources_detected(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_stale_datasources()
        f = suite.findings[0]
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_extract_encryption_enforced(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_extract_encryption()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_remote_query_agent_none(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_remote_query_agent()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_remote_query_agent_detected(self, full_scan_data):
        full_scan_data["datasources"][0]["use_remote_query_agent"] = True
        suite = DataSecurityChecks(full_scan_data)
        suite._check_remote_query_agent()
        assert suite.findings[0].status == Status.WARN

    @pytest.mark.unit
    def test_multi_connection_datasources(self, full_scan_data):
        suite = DataSecurityChecks(full_scan_data)
        suite._check_multi_connection_datasources()
        # All fixture datasources have 1 connection
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_uncertified_in_sensitive_projects_detected(self, full_scan_data):
        # Rename a project to trigger sensitive keyword matching
        full_scan_data["projects"][1]["name"] = "Finance HR Reports"
        suite = DataSecurityChecks(full_scan_data)
        suite._check_uncertified_in_sensitive_projects()
        f = suite.findings[0]
        assert f.check_id == "DATA-009"
        # ds-002 is uncertified and in project p-002 ("Finance HR Reports")
        assert f.status == Status.FAIL


class TestAPIChecks:
    """API-001 through API-009."""

    @pytest.mark.unit
    def test_revision_history_enabled(self, full_scan_data):
        suite = APIChecks(full_scan_data)
        suite._check_revision_history()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_revision_history_disabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["revision_history_enabled"] = False
        suite = APIChecks(full_scan_data)
        suite._check_revision_history()
        assert suite.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_content_sprawl_low_ratio(self, full_scan_data):
        suite = APIChecks(full_scan_data)
        suite._check_content_sprawl()
        f = suite.findings[0]
        assert f.status == Status.PASS

    @pytest.mark.unit
    def test_stale_flows_none(self, full_scan_data):
        suite = APIChecks(full_scan_data)
        suite._check_stale_flows()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_data_driven_alerts_enabled_warns(self, full_scan_data):
        suite = APIChecks(full_scan_data)
        suite._check_data_driven_alerts()
        f = suite.findings[0]
        assert f.check_id == "API-008"
        assert f.status == Status.WARN  # fixture has data_alerts_enabled=True

    @pytest.mark.unit
    def test_ask_data_enabled_warns(self, full_scan_data):
        suite = APIChecks(full_scan_data)
        suite._check_ask_data_mode()
        f = suite.findings[0]
        assert f.check_id == "API-009"
        assert f.status == Status.WARN  # fixture has ask_data_mode="EnabledByDefault"

    @pytest.mark.unit
    def test_ask_data_disabled_passes(self, full_scan_data):
        full_scan_data["site_settings"]["ask_data_mode"] = "DisabledByDefault"
        suite = APIChecks(full_scan_data)
        suite._check_ask_data_mode()
        assert suite.findings[0].status == Status.PASS


class TestLoggingChecks:
    """LOG-001 through LOG-009."""

    @pytest.mark.unit
    def test_catalog_enabled_passes(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_catalog_enabled()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_catalog_disabled_fails(self, full_scan_data):
        full_scan_data["site_settings"]["catalog_enabled"] = False
        suite = LoggingChecks(full_scan_data)
        suite._check_catalog_enabled()
        assert suite.findings[0].status == Status.FAIL

    @pytest.mark.unit
    def test_orphaned_content_none(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_orphaned_content()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_access_review_readiness(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_access_review_readiness()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_admin_mode_content_and_users_warns(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_admin_mode()
        f = suite.findings[0]
        assert f.check_id == "LOG-007"
        assert f.status == Status.WARN  # fixture has admin_mode="ContentAndUsers"

    @pytest.mark.unit
    def test_admin_mode_content_only_passes(self, full_scan_data):
        full_scan_data["site_settings"]["admin_mode"] = "ContentOnly"
        suite = LoggingChecks(full_scan_data)
        suite._check_admin_mode()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_content_ownership_distribution(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_content_ownership_distribution()
        f = suite.findings[0]
        assert f.check_id == "LOG-008"
        # All content owned by u-003 in fixture — concentrated
        assert f.status in (Status.WARN, Status.FAIL)

    @pytest.mark.unit
    def test_site_state_active_passes(self, full_scan_data):
        suite = LoggingChecks(full_scan_data)
        suite._check_site_state()
        assert suite.findings[0].status == Status.PASS

    @pytest.mark.unit
    def test_site_state_suspended_fails(self, full_scan_data):
        full_scan_data["site_settings"]["state"] = "Suspended"
        suite = LoggingChecks(full_scan_data)
        suite._check_site_state()
        assert suite.findings[0].status == Status.FAIL


class TestFullScan:
    """End-to-end scan using fixture data."""

    @pytest.mark.unit
    def test_run_all_returns_45_findings(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        assert len(findings) == 45

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
    def test_nine_checks_per_domain(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        for cat in Category:
            domain_findings = [f for f in findings if f.category == cat]
            assert len(domain_findings) == 9, f"{cat.value} has {len(domain_findings)} checks, expected 9"

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

    @pytest.mark.unit
    def test_check_ids_unique(self, full_scan_data):
        checks = SecurityChecks(full_scan_data)
        findings = checks.run_all()
        ids = [f.check_id for f in findings]
        assert len(ids) == len(set(ids)), f"Duplicate check IDs: {[x for x in ids if ids.count(x) > 1]}"
