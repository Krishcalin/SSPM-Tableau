"""Tableau Cloud REST API data collector.

Authenticates via Personal Access Token and pulls configuration
data from all relevant API endpoints (read-only).
"""

from __future__ import annotations

import logging
import time

import tableauserverclient as TSC

logger = logging.getLogger(__name__)

# Defaults for resilience
_CONNECT_TIMEOUT = 30  # seconds
_READ_TIMEOUT = 120  # seconds
_MAX_RETRIES = 3
_BACKOFF_BASE = 2  # exponential backoff base


def _retry(func, description: str, retries: int = _MAX_RETRIES):
    """Execute *func* with exponential-backoff retry on transient errors."""
    for attempt in range(1, retries + 1):
        try:
            return func()
        except (OSError, TimeoutError, ConnectionError) as exc:
            if attempt == retries:
                logger.error("%s failed after %d attempts: %s", description, retries, exc)
                raise
            wait = _BACKOFF_BASE ** attempt
            logger.warning(
                "%s attempt %d/%d failed (%s), retrying in %ds",
                description, attempt, retries, exc, wait,
            )
            time.sleep(wait)


class TableauCollector:
    """Connects to Tableau Cloud and collects configuration data."""

    def __init__(self, server_url: str, site_id: str, token_name: str, token_secret: str):
        if not server_url or not server_url.startswith("http"):
            raise ValueError(f"Invalid server URL: {server_url!r}")
        if not token_name or not token_secret:
            raise ValueError("PAT token name and secret must not be empty")
        self.server_url = server_url
        self.site_id = site_id
        self.token_name = token_name
        self.token_secret = token_secret
        self.server: TSC.Server | None = None
        self.data: dict = {}

    def connect(self) -> None:
        """Authenticate to Tableau Cloud."""
        logger.info("Connecting to %s (site: %s)", self.server_url, self.site_id)
        tableau_auth = TSC.PersonalAccessTokenAuth(
            self.token_name, self.token_secret, site_id=self.site_id
        )
        self.server = TSC.Server(self.server_url, use_server_version=True)
        self.server.add_http_options({
            "timeout": (_CONNECT_TIMEOUT, _READ_TIMEOUT),
        })

        def _sign_in():
            self.server.auth.sign_in(tableau_auth)

        _retry(_sign_in, "Authentication")
        logger.info("Authenticated successfully (API v%s)", self.server.version)

    def collect_all(self) -> dict:
        """Pull all configuration data from the API."""
        self.data["users"] = self._collect_users()
        self.data["groups"] = self._collect_groups()
        self.data["projects"] = self._collect_projects()
        self.data["datasources"] = self._collect_datasources()
        self.data["workbooks"] = self._collect_workbooks()
        self.data["site_settings"] = self._collect_site_settings()
        self.data["schedules"] = self._collect_schedules()
        self.data["flows"] = self._collect_flows()
        return self.data

    def _collect_users(self) -> list[dict]:
        logger.info("Collecting users...")
        users: list[dict] = []

        def _fetch():
            for user in TSC.Pager(self.server.users):
                try:
                    self.server.users.populate_workbooks(user)
                except TSC.ServerResponseError as exc:
                    logger.warning("Could not populate workbooks for user %s: %s", user.name, exc)
                users.append({
                    "id": user.id,
                    "name": user.name,
                    "fullname": user.fullname,
                    "site_role": user.site_role,
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "auth_setting": getattr(user, "auth_setting", None),
                    "domain_name": getattr(user, "domain_name", None),
                    "workbook_count": len(user.workbooks) if user.workbooks else 0,
                })

        _retry(_fetch, "User collection")
        logger.info("  %d users found", len(users))
        return users

    def _collect_groups(self) -> list[dict]:
        logger.info("Collecting groups...")
        groups: list[dict] = []

        def _fetch():
            for group in TSC.Pager(self.server.groups):
                group_info: dict = {
                    "id": group.id,
                    "name": group.name,
                    "domain_name": getattr(group, "domain_name", None),
                    "license_mode": getattr(group, "license_mode", None),
                    "minimum_site_role": getattr(group, "minimum_site_role", None),
                }
                try:
                    self.server.groups.populate_users(group)
                    group_info["user_count"] = len(group.users) if group.users else 0
                    group_info["users"] = [
                        {"id": u.id, "name": u.name, "site_role": u.site_role}
                        for u in (group.users or [])
                    ]
                except TSC.ServerResponseError as exc:
                    logger.warning("Could not populate users for group %s: %s", group.name, exc)
                    group_info["user_count"] = 0
                    group_info["users"] = []
                groups.append(group_info)

        _retry(_fetch, "Group collection")
        logger.info("  %d groups found", len(groups))
        return groups

    def _collect_projects(self) -> list[dict]:
        logger.info("Collecting projects...")
        projects: list[dict] = []

        def _fetch():
            for project in TSC.Pager(self.server.projects):
                projects.append({
                    "id": project.id,
                    "name": project.name,
                    "content_permissions": getattr(project, "content_permissions", None),
                    "parent_id": project.parent_id,
                    "owner_id": getattr(project, "owner_id", None),
                    "description": project.description,
                })

        _retry(_fetch, "Project collection")
        logger.info("  %d projects found", len(projects))
        return projects

    def _collect_datasources(self) -> list[dict]:
        logger.info("Collecting data sources...")
        datasources: list[dict] = []

        def _fetch():
            for ds in TSC.Pager(self.server.datasources):
                ds_info: dict = {
                    "id": ds.id,
                    "name": ds.name,
                    "content_url": ds.content_url,
                    "datasource_type": ds.datasource_type,
                    "created_at": ds.created_at.isoformat() if ds.created_at else None,
                    "updated_at": ds.updated_at.isoformat() if ds.updated_at else None,
                    "project_id": ds.project_id,
                    "project_name": ds.project_name,
                    "owner_id": ds.owner_id,
                    "has_extracts": ds.has_extracts,
                    "is_certified": getattr(ds, "certified", False),
                    "use_remote_query_agent": getattr(ds, "use_remote_query_agent", False),
                }
                try:
                    self.server.datasources.populate_connections(ds)
                    connections = []
                    for conn in (ds.connections or []):
                        connections.append({
                            "id": conn.id,
                            "connection_type": conn.connection_type,
                            "server_address": getattr(conn, "server_address", None),
                            "username": getattr(conn, "username", None),
                            "embed_password": getattr(conn, "embed_password", None),
                        })
                    ds_info["connections"] = connections
                except TSC.ServerResponseError as exc:
                    logger.warning("Could not populate connections for datasource %s: %s", ds.name, exc)
                    ds_info["connections"] = []
                datasources.append(ds_info)

        _retry(_fetch, "Data source collection")
        logger.info("  %d data sources found", len(datasources))
        return datasources

    def _collect_workbooks(self) -> list[dict]:
        logger.info("Collecting workbooks...")
        workbooks: list[dict] = []

        def _fetch():
            for wb in TSC.Pager(self.server.workbooks):
                workbooks.append({
                    "id": wb.id,
                    "name": wb.name,
                    "project_id": wb.project_id,
                    "project_name": wb.project_name,
                    "owner_id": wb.owner_id,
                    "created_at": wb.created_at.isoformat() if wb.created_at else None,
                    "updated_at": wb.updated_at.isoformat() if wb.updated_at else None,
                    "size": getattr(wb, "size", None),
                    "show_tabs": getattr(wb, "show_tabs", None),
                })

        _retry(_fetch, "Workbook collection")
        logger.info("  %d workbooks found", len(workbooks))
        return workbooks

    def _collect_site_settings(self) -> dict:
        logger.info("Collecting site settings...")
        try:
            site = self.server.sites.get_by_id(self.server.site_id)
            settings = {
                "id": site.id,
                "name": site.name,
                "content_url": site.content_url,
                "state": site.state,
                "admin_mode": getattr(site, "admin_mode", None),
                "revision_history_enabled": getattr(site, "revision_history_enabled", None),
                "revision_limit": getattr(site, "revision_limit", None),
                "subscribe_others_enabled": getattr(site, "subscribe_others_enabled", None),
                "guest_access_enabled": getattr(site, "guest_access_enabled", None),
                "cache_warmup_enabled": getattr(site, "cache_warmup_enabled", None),
                "commenting_enabled": getattr(site, "commenting_enabled", None),
                "flows_enabled": getattr(site, "flows_enabled", None),
                "extract_encryption_mode": getattr(site, "extract_encryption_mode", None),
                "request_access_enabled": getattr(site, "request_access_enabled", None),
                "run_now_enabled": getattr(site, "run_now_enabled", None),
                "user_visibility": getattr(site, "user_visibility", None),
                "data_alerts_enabled": getattr(site, "data_alerts_enabled", None),
                "commenting_mentions_enabled": getattr(site, "commenting_mentions_enabled", None),
                "catalog_enabled": getattr(site, "catalog_enabled", None),
                "derived_permissions_enabled": getattr(site, "derived_permissions_enabled", None),
                "ask_data_mode": getattr(site, "ask_data_mode", None),
            }
            logger.info("  Site: %s", site.name)
            return settings
        except TSC.ServerResponseError as exc:
            logger.warning("Could not retrieve site settings: %s", exc)
            return {}

    def _collect_schedules(self) -> list[dict]:
        logger.info("Collecting schedules...")
        schedules: list[dict] = []
        try:
            for sched in TSC.Pager(self.server.schedules):
                schedules.append({
                    "id": sched.id,
                    "name": sched.name,
                    "schedule_type": sched.schedule_type,
                    "state": sched.state,
                    "priority": getattr(sched, "priority", None),
                    "frequency": getattr(sched, "frequency", None),
                    "next_run_at": sched.next_run_at.isoformat() if getattr(sched, "next_run_at", None) else None,
                    "created_at": sched.created_at.isoformat() if getattr(sched, "created_at", None) else None,
                })
        except TSC.ServerResponseError as exc:
            logger.warning("Could not collect schedules: %s", exc)
        logger.info("  %d schedules found", len(schedules))
        return schedules

    def _collect_flows(self) -> list[dict]:
        logger.info("Collecting flows...")
        flows: list[dict] = []
        try:
            for flow in TSC.Pager(self.server.flows):
                flows.append({
                    "id": flow.id,
                    "name": flow.name,
                    "project_id": flow.project_id,
                    "project_name": flow.project_name,
                    "owner_id": flow.owner_id,
                    "created_at": flow.created_at.isoformat() if flow.created_at else None,
                    "updated_at": flow.updated_at.isoformat() if flow.updated_at else None,
                })
        except TSC.ServerResponseError as exc:
            logger.warning("Could not collect flows: %s", exc)
        logger.info("  %d flows found", len(flows))
        return flows

    def disconnect(self) -> None:
        if self.server:
            try:
                self.server.auth.sign_out()
            except Exception:  # noqa: BLE001 — best-effort sign-out
                logger.debug("Sign-out failed (non-critical)")
            logger.info("Disconnected")
