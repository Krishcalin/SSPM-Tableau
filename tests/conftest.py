"""Shared test fixtures for SSPM scanner tests."""

import pytest
from datetime import datetime, timezone, timedelta


@pytest.fixture
def sample_users():
    """Realistic set of Tableau Cloud users."""
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "u-001", "name": "admin@corp.com", "fullname": "Site Admin",
            "site_role": "SiteAdministratorCreator", "auth_setting": "SAML",
            "last_login": (now - timedelta(days=1)).isoformat(),
            "domain_name": "corp.com", "workbook_count": 5,
        },
        {
            "id": "u-002", "name": "breakglass@corp.com", "fullname": "Break Glass",
            "site_role": "SiteAdministratorCreator", "auth_setting": "ServerDefault",
            "last_login": (now - timedelta(days=60)).isoformat(),
            "domain_name": "local", "workbook_count": 0,
        },
        {
            "id": "u-003", "name": "analyst@corp.com", "fullname": "Data Analyst",
            "site_role": "Creator", "auth_setting": "SAML",
            "last_login": (now - timedelta(days=5)).isoformat(),
            "domain_name": "corp.com", "workbook_count": 12,
        },
        {
            "id": "u-004", "name": "viewer@corp.com", "fullname": "Report Viewer",
            "site_role": "Viewer", "auth_setting": "SAML",
            "last_login": (now - timedelta(days=3)).isoformat(),
            "domain_name": "corp.com", "workbook_count": 0,
        },
        {
            "id": "u-005", "name": "stale@corp.com", "fullname": "Stale User",
            "site_role": "Explorer", "auth_setting": "SAML",
            "last_login": (now - timedelta(days=120)).isoformat(),
            "domain_name": "corp.com", "workbook_count": 2,
        },
        {
            "id": "u-006", "name": "never@corp.com", "fullname": "Never Logged In",
            "site_role": "Viewer", "auth_setting": "SAML",
            "last_login": None,
            "domain_name": "corp.com", "workbook_count": 0,
        },
        {
            "id": "u-007", "name": "idle-creator@corp.com", "fullname": "Idle Creator",
            "site_role": "Creator", "auth_setting": "SAML",
            "last_login": (now - timedelta(days=10)).isoformat(),
            "domain_name": "corp.com", "workbook_count": 0,
        },
    ]


@pytest.fixture
def sample_groups():
    return [
        {"id": "g-001", "name": "All Users", "domain_name": None,
         "license_mode": None, "minimum_site_role": None,
         "user_count": 7, "users": []},
        {"id": "g-002", "name": "Finance Team", "domain_name": "corp.com",
         "license_mode": None, "minimum_site_role": None,
         "user_count": 3, "users": []},
        {"id": "g-003", "name": "Engineering", "domain_name": "corp.com",
         "license_mode": None, "minimum_site_role": None,
         "user_count": 4, "users": []},
        {"id": "g-004", "name": "Data Stewards", "domain_name": "corp.com",
         "license_mode": None, "minimum_site_role": None,
         "user_count": 2, "users": []},
    ]


@pytest.fixture
def sample_projects():
    return [
        {"id": "p-001", "name": "Default", "content_permissions": "ManagedByOwner",
         "parent_id": None, "owner_id": "u-001", "description": ""},
        {"id": "p-002", "name": "Finance Reports", "content_permissions": "LockedToProject",
         "parent_id": None, "owner_id": "u-001", "description": "Governed finance content"},
        {"id": "p-003", "name": "Engineering Dashboards", "content_permissions": "LockedToProject",
         "parent_id": None, "owner_id": "u-001", "description": ""},
        {"id": "p-004", "name": "Sandbox", "content_permissions": "ManagedByOwner",
         "parent_id": None, "owner_id": "u-003", "description": "Experimentation"},
    ]


@pytest.fixture
def sample_datasources():
    now = datetime.now(timezone.utc)
    return [
        {
            "id": "ds-001", "name": "Sales Pipeline", "content_url": "sales",
            "datasource_type": "sqlserver", "project_id": "p-002",
            "project_name": "Finance Reports", "owner_id": "u-003",
            "created_at": (now - timedelta(days=90)).isoformat(),
            "updated_at": (now - timedelta(days=5)).isoformat(),
            "has_extracts": True, "is_certified": True,
            "use_remote_query_agent": False,
            "connections": [
                {"id": "c-001", "connection_type": "sqlserver",
                 "server_address": "db.corp.com", "username": "svc_tableau",
                 "embed_password": True},
            ],
        },
        {
            "id": "ds-002", "name": "Employee PII Data", "content_url": "pii",
            "datasource_type": "postgres", "project_id": "p-002",
            "project_name": "Finance Reports", "owner_id": "u-003",
            "created_at": (now - timedelta(days=200)).isoformat(),
            "updated_at": (now - timedelta(days=200)).isoformat(),
            "has_extracts": True, "is_certified": False,
            "use_remote_query_agent": False,
            "connections": [
                {"id": "c-002", "connection_type": "postgres",
                 "server_address": "hr-db.corp.com", "username": "hr_read",
                 "embed_password": True},
            ],
        },
        {
            "id": "ds-003", "name": "Web Analytics", "content_url": "web",
            "datasource_type": "bigquery", "project_id": "p-003",
            "project_name": "Engineering Dashboards", "owner_id": "u-003",
            "created_at": (now - timedelta(days=30)).isoformat(),
            "updated_at": (now - timedelta(days=2)).isoformat(),
            "has_extracts": False, "is_certified": True,
            "use_remote_query_agent": False,
            "connections": [
                {"id": "c-003", "connection_type": "bigquery",
                 "server_address": None, "username": None,
                 "embed_password": False},
            ],
        },
    ]


@pytest.fixture
def sample_workbooks():
    now = datetime.now(timezone.utc)
    return [
        {"id": "wb-001", "name": "Q4 Revenue Dashboard", "project_id": "p-002",
         "project_name": "Finance Reports", "owner_id": "u-003",
         "created_at": (now - timedelta(days=60)).isoformat(),
         "updated_at": (now - timedelta(days=3)).isoformat(),
         "size": 5000000, "show_tabs": True},
        {"id": "wb-002", "name": "Engineering Metrics", "project_id": "p-003",
         "project_name": "Engineering Dashboards", "owner_id": "u-003",
         "created_at": (now - timedelta(days=30)).isoformat(),
         "updated_at": (now - timedelta(days=1)).isoformat(),
         "size": 3000000, "show_tabs": False},
    ]


@pytest.fixture
def sample_site_settings():
    return {
        "id": "site-001", "name": "CorpAnalytics", "content_url": "corp",
        "state": "Active", "admin_mode": "ContentAndUsers",
        "revision_history_enabled": True, "revision_limit": 25,
        "subscribe_others_enabled": True, "guest_access_enabled": False,
        "cache_warmup_enabled": False, "commenting_enabled": True,
        "flows_enabled": True, "extract_encryption_mode": "enforced",
        "request_access_enabled": True, "run_now_enabled": True,
        "user_visibility": "FULL", "data_alerts_enabled": True,
        "commenting_mentions_enabled": True, "catalog_enabled": True,
        "derived_permissions_enabled": True, "ask_data_mode": "EnabledByDefault",
    }


@pytest.fixture
def full_scan_data(sample_users, sample_groups, sample_projects,
                   sample_datasources, sample_workbooks, sample_site_settings):
    """Complete dataset for a full scan."""
    return {
        "users": sample_users,
        "groups": sample_groups,
        "projects": sample_projects,
        "datasources": sample_datasources,
        "workbooks": sample_workbooks,
        "site_settings": sample_site_settings,
        "schedules": [],
        "flows": [],
    }
