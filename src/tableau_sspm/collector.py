"""Tableau Cloud REST API data collector.

Authenticates via Personal Access Token and pulls configuration
data from all relevant API endpoints (read-only).
"""

import tableauserverclient as TSC


class TableauCollector:
    """Connects to Tableau Cloud and collects configuration data."""

    def __init__(self, server_url: str, site_id: str, token_name: str, token_secret: str):
        self.server_url = server_url
        self.site_id = site_id
        self.token_name = token_name
        self.token_secret = token_secret
        self.server = None
        self.data: dict = {}

    def connect(self):
        """Authenticate to Tableau Cloud."""
        print(f"  ├─ Connecting to {self.server_url} (site: {self.site_id})")
        tableau_auth = TSC.PersonalAccessTokenAuth(
            self.token_name, self.token_secret, site_id=self.site_id
        )
        self.server = TSC.Server(self.server_url, use_server_version=True)
        self.server.auth.sign_in(tableau_auth)
        print(f"  ├─ Authenticated successfully (API v{self.server.version})")

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
        print("  ├─ Collecting users...")
        users = []
        for user in TSC.Pager(self.server.users):
            self.server.users.populate_workbooks(user)
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
        print(f"  │   └─ {len(users)} users found")
        return users

    def _collect_groups(self) -> list[dict]:
        print("  ├─ Collecting groups...")
        groups = []
        for group in TSC.Pager(self.server.groups):
            group_info = {
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
            except Exception:
                group_info["user_count"] = 0
                group_info["users"] = []
            groups.append(group_info)
        print(f"  │   └─ {len(groups)} groups found")
        return groups

    def _collect_projects(self) -> list[dict]:
        print("  ├─ Collecting projects...")
        projects = []
        for project in TSC.Pager(self.server.projects):
            projects.append({
                "id": project.id,
                "name": project.name,
                "content_permissions": getattr(project, "content_permissions", None),
                "parent_id": project.parent_id,
                "owner_id": getattr(project, "owner_id", None),
                "description": project.description,
            })
        print(f"  │   └─ {len(projects)} projects found")
        return projects

    def _collect_datasources(self) -> list[dict]:
        print("  ├─ Collecting data sources...")
        datasources = []
        for ds in TSC.Pager(self.server.datasources):
            ds_info = {
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
            except Exception:
                ds_info["connections"] = []
            datasources.append(ds_info)
        print(f"  │   └─ {len(datasources)} data sources found")
        return datasources

    def _collect_workbooks(self) -> list[dict]:
        print("  ├─ Collecting workbooks...")
        workbooks = []
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
        print(f"  │   └─ {len(workbooks)} workbooks found")
        return workbooks

    def _collect_site_settings(self) -> dict:
        print("  ├─ Collecting site settings...")
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
            print(f"  │   └─ Site: {site.name}")
            return settings
        except Exception as e:
            print(f"  │   └─ Warning: Could not retrieve site settings ({e})")
            return {}

    def _collect_schedules(self) -> list[dict]:
        print("  ├─ Collecting schedules...")
        schedules = []
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
        except Exception:
            pass
        print(f"  │   └─ {len(schedules)} schedules found")
        return schedules

    def _collect_flows(self) -> list[dict]:
        print("  ├─ Collecting flows...")
        flows = []
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
        except Exception:
            pass
        print(f"  │   └─ {len(flows)} flows found")
        return flows

    def disconnect(self):
        if self.server:
            self.server.auth.sign_out()
            print("  └─ Disconnected\n")
