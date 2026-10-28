from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult, now_iso


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, target TEXT NOT NULL, profile TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  requests INTEGER NOT NULL DEFAULT 0, pages INTEGER NOT NULL DEFAULT 0,
  discovered INTEGER NOT NULL DEFAULT 0, discovered_http INTEGER NOT NULL DEFAULT 0,
  discovered_browser INTEGER NOT NULL DEFAULT 0, findings INTEGER NOT NULL DEFAULT 0,
  errors_json TEXT NOT NULL DEFAULT '[]', baseline_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, rule_id TEXT NOT NULL,
  title TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, url TEXT NOT NULL,
  description TEXT NOT NULL, evidence_json TEXT NOT NULL, remediation TEXT NOT NULL,
  category TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS schedules (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  profile TEXT NOT NULL,
  interval_minutes INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  allow_private INTEGER NOT NULL DEFAULT 0,
  openapi_url TEXT,
  browser_crawl INTEGER NOT NULL DEFAULT 0,
  graphql INTEGER NOT NULL DEFAULT 0,
  graphql_url TEXT,
  webhook_url TEXT,
  created_at TEXT NOT NULL,
  next_run_at TEXT NOT NULL,
  last_run_at TEXT,
  last_scan_id TEXT
);
CREATE TABLE IF NOT EXISTS login_flows (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  flow_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  sso_subject TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sso_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sso_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  provider TEXT NOT NULL,
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  finding_key TEXT NOT NULL UNIQUE,
  scan_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  provider TEXT NOT NULL,
  external_id TEXT NOT NULL,
  external_url TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_sync_at TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  profile TEXT NOT NULL,
  concurrency INTEGER NOT NULL,
  options_json TEXT NOT NULL,
  targets_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tickets_scan ON tickets(scan_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
"""

COVERAGE_COLUMNS = (
    ("discovered_http", "INTEGER NOT NULL DEFAULT 0"),
    ("discovered_browser", "INTEGER NOT NULL DEFAULT 0"),
    ("baseline_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("campaign_id", "TEXT"),
    ("tenant_id", "TEXT NOT NULL DEFAULT 'default'"),
)
USER_COLUMNS = (
    ("tenant_id", "TEXT NOT NULL DEFAULT 'default'"),
    ("sso_subject", "TEXT"),
)


class Storage:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            self._migrate(db)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def _migrate(self, db: sqlite3.Connection) -> None:
        existing = {row["name"] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
        for name, declaration in COVERAGE_COLUMNS:
            if name not in existing:
                db.execute(f"ALTER TABLE scans ADD COLUMN {name} {declaration}")
        user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        for name, declaration in USER_COLUMNS:
            if user_cols and name not in user_cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
        db.execute(
            "INSERT OR IGNORE INTO tenants(id,name,slug,created_at) VALUES('default','Default','default',?)",
            (now_iso(),),
        )

    def create_scan(self, result: ScanResult, *, tenant_id: str = "default") -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO scans(id,target,profile,status,created_at,tenant_id) VALUES(?,?,?,?,?,?)",
                (result.scan_id, result.target, result.profile, result.status, result.created_at, tenant_id),
            )

    def update_scan(self, result: ScanResult) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE scans SET status=?,started_at=?,finished_at=?,requests=?,pages=?,discovered=?,
                discovered_http=?,discovered_browser=?,findings=?,errors_json=?,baseline_json=? WHERE id=?""",
                (
                    result.status, result.started_at, result.finished_at, result.stats.requests,
                    result.stats.pages, result.stats.discovered, result.stats.discovered_http,
                    result.stats.discovered_browser, len(result.findings), json.dumps(result.errors),
                    json.dumps(result.baseline or {}), result.scan_id,
                ),
            )

    def previous_completed_scan(self, target: str, *, before_scan_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                """SELECT id FROM scans WHERE target=? AND status='completed' AND id!=?
                ORDER BY COALESCE(finished_at, created_at) DESC LIMIT 1""",
                (target, before_scan_id),
            ).fetchone()
        if row is None:
            return None
        return self.get_scan(row["id"])

    def replace_findings(self, scan_id: str, findings: list[Finding]) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            db.executemany(
                """INSERT INTO findings(scan_id,rule_id,title,severity,confidence,url,description,evidence_json,remediation,category,verified)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                [(scan_id, item.rule_id, item.title, item.severity, item.confidence, item.url, item.description,
                  json.dumps(item.evidence, ensure_ascii=False), item.remediation, item.category, int(item.verified))
                 for item in findings],
            )

    def list_scans(self, limit: int = 100, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if tenant_id:
                rows = db.execute(
                    "SELECT * FROM scans WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["errors"] = json.loads(item.pop("errors_json"))
            item["baseline"] = json.loads(item.pop("baseline_json", "{}") or "{}")
            result.append(item)
        return result

    def delete_scan(self, scan_id: str) -> bool:
        with self.connect() as db:
            db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            cursor = db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
            return cursor.rowcount > 0

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = db.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        data = dict(row)
        data["errors"] = json.loads(data.pop("errors_json"))
        baseline_raw = data.pop("baseline_json", "{}") or "{}"
        data["baseline"] = json.loads(baseline_raw)
        data["findings_list"] = [dict(item) | {"evidence": json.loads(item["evidence_json"])} for item in findings]
        for item in data["findings_list"]:
            item.pop("evidence_json", None)
        return data

    def list_findings(self, limit: int = 500) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT findings.*, scans.target FROM findings JOIN scans ON scans.id=findings.scan_id ORDER BY findings.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            result.append(item)
        return result

    def dashboard(self) -> dict[str, Any]:
        with self.connect() as db:
            scans = db.execute("SELECT status, COUNT(*) count FROM scans GROUP BY status").fetchall()
            severities = db.execute("SELECT severity, COUNT(*) count FROM findings GROUP BY severity").fetchall()
            total_scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            schedules = db.execute("SELECT COUNT(*) FROM schedules WHERE enabled=1").fetchone()[0]
        return {
            "generated_at": now_iso(), "total_scans": total_scans, "total_findings": total_findings,
            "active_schedules": schedules,
            "scans_by_status": {row["status"]: row["count"] for row in scans},
            "findings_by_severity": {row["severity"]: row["count"] for row in severities},
        }

    def create_schedule(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO schedules(
                    id,target,profile,interval_minutes,enabled,allow_private,openapi_url,browser_crawl,
                    graphql,graphql_url,webhook_url,created_at,next_run_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    item["id"], item["target"], item["profile"], item["interval_minutes"],
                    int(item.get("enabled", True)), int(item.get("allow_private", False)),
                    item.get("openapi_url"), int(item.get("browser_crawl", False)),
                    int(item.get("graphql", False)), item.get("graphql_url"), item.get("webhook_url"),
                    item["created_at"], item["next_run_at"],
                ),
            )

    def list_schedules(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def delete_schedule(self, schedule_id: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
            return cursor.rowcount > 0

    def due_schedules(self, now: str) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at",
                (now,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_schedule_run(self, schedule_id: str, *, next_run_at: str, last_run_at: str, last_scan_id: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE schedules SET next_run_at=?, last_run_at=?, last_scan_id=? WHERE id=?",
                (next_run_at, last_run_at, last_scan_id, schedule_id),
            )

    def save_login_flow(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO login_flows(id,name,flow_json,created_at,updated_at) VALUES(?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, flow_json=excluded.flow_json, updated_at=excluded.updated_at""",
                (item["id"], item["name"], json.dumps(item["flow"]), item["created_at"], item["updated_at"]),
            )

    def list_login_flows(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM login_flows ORDER BY updated_at DESC").fetchall()
        return [
            {
                "id": row["id"], "name": row["name"], "flow": json.loads(row["flow_json"]),
                "created_at": row["created_at"], "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def get_login_flow(self, flow_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM login_flows WHERE id=?", (flow_id,)).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"], "name": row["name"], "flow": json.loads(row["flow_json"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def delete_login_flow(self, flow_id: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM login_flows WHERE id=?", (flow_id,))
            return cursor.rowcount > 0

    def unique_login_flow_name(self, desired: str, *, exclude_id: str | None = None) -> str:
        """Avoid duplicate display names when recording/saving multiple flows."""
        base = (desired or "login-flow").strip()[:70] or "login-flow"
        existing = {
            item["name"]
            for item in self.list_login_flows()
            if exclude_id is None or item["id"] != exclude_id
        }
        if base not in existing:
            return base
        for index in range(2, 1000):
            candidate = f"{base}-{index}"
            if candidate not in existing:
                return candidate
        return f"{base}-{secrets.token_hex(3)}"

    def create_user(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO users(id,name,role,token_hash,tenant_id,sso_subject,created_at) VALUES(?,?,?,?,?,?,?)",
                (
                    item["id"], item["name"], item["role"], item["token_hash"],
                    item.get("tenant_id", "default"), item.get("sso_subject"),
                    item.get("created_at", now_iso()),
                ),
            )

    def list_users(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as db:
            if tenant_id:
                rows = db.execute(
                    "SELECT id,name,role,tenant_id,created_at FROM users WHERE tenant_id=? ORDER BY created_at",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id,name,role,tenant_id,created_at FROM users ORDER BY created_at"
                ).fetchall()
        return [dict(row) for row in rows]

    def create_tenant(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO tenants(id,name,slug,created_at) VALUES(?,?,?,?)",
                (item["id"], item["name"], item["slug"], item.get("created_at", now_iso())),
            )

    def list_tenants(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM tenants ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def set_sso_config(self, config: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO sso_config(id,config_json,updated_at) VALUES(1,?,?)
                ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json, updated_at=excluded.updated_at""",
                (json.dumps(config), now_iso()),
            )

    def get_sso_config(self) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT config_json, updated_at FROM sso_config WHERE id=1").fetchone()
        if row is None:
            return None
        return {"config": json.loads(row["config_json"]), "updated_at": row["updated_at"]}

    def save_sso_state(self, state: str, nonce: str, tenant_id: str) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO sso_states(state,nonce,tenant_id,created_at) VALUES(?,?,?,?)",
                (state, nonce, tenant_id, now_iso()),
            )

    def consume_sso_state(self, state: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM sso_states WHERE state=?", (state,)).fetchone()
            if row is None:
                return None
            db.execute("DELETE FROM sso_states WHERE state=?", (state,))
        return dict(row)

    def find_user_by_sso_subject(self, subject: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT id,name,role,tenant_id,token_hash FROM users WHERE sso_subject=?", (subject,),
            ).fetchone()
        return dict(row) if row else None

    def user_count(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def authenticate_token(self, token: str) -> dict[str, Any] | None:
        from .team import constant_time_hash_equals, hash_token
        digest = hash_token(token)
        with self.connect() as db:
            rows = db.execute("SELECT id,name,role,tenant_id,token_hash FROM users").fetchall()
        for row in rows:
            if constant_time_hash_equals(row["token_hash"], digest):
                return {
                    "id": row["id"], "name": row["name"], "role": row["role"],
                    "tenant_id": row["tenant_id"] or "default",
                }
        return None

    def set_ticket_config(self, provider: str, config: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO ticket_config(id,provider,config_json,updated_at) VALUES(1,?,?,?)
                ON CONFLICT(id) DO UPDATE SET provider=excluded.provider, config_json=excluded.config_json,
                updated_at=excluded.updated_at""",
                (provider, json.dumps(config), now_iso()),
            )

    def get_ticket_config(self) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT provider, config_json, updated_at FROM ticket_config WHERE id=1").fetchone()
        if row is None:
            return None
        return {"provider": row["provider"], "config": json.loads(row["config_json"]), "updated_at": row["updated_at"]}

    def upsert_ticket(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO tickets(
                    id,finding_key,scan_id,rule_id,title,severity,provider,external_id,external_url,status,created_at,last_sync_at,meta_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(finding_key) DO UPDATE SET
                    status=excluded.status, external_url=excluded.external_url, last_sync_at=excluded.last_sync_at,
                    meta_json=excluded.meta_json""",
                (
                    item["id"], item["finding_key"], item["scan_id"], item["rule_id"], item["title"], item["severity"],
                    item["provider"], item["external_id"], item["external_url"], item["status"],
                    item["created_at"], item["last_sync_at"], json.dumps(item.get("meta") or {}),
                ),
            )

    def list_tickets(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM tickets ORDER BY last_sync_at DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["meta"] = json.loads(item.pop("meta_json") or "{}")
            result.append(item)
        return result

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["meta"] = json.loads(item.pop("meta_json") or "{}")
        return item

    def create_campaign(self, item: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO campaigns(id,name,status,profile,concurrency,options_json,targets_json,created_at,finished_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    item["id"], item["name"], item["status"], item["profile"], item["concurrency"],
                    json.dumps(item.get("options") or {}), json.dumps(item.get("targets") or []),
                    item["created_at"], item.get("finished_at"),
                ),
            )

    def list_campaigns(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
        return [self._campaign_row(row) for row in rows]

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        return None if row is None else self._campaign_row(row)

    def update_campaign_status(self, campaign_id: str, status: str, *, finished_at: str | None) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE campaigns SET status=?, finished_at=? WHERE id=?",
                (status, finished_at, campaign_id),
            )

    def update_campaign_target(
        self, campaign_id: str, target: str, *, status: str, scan_id: str | None,
    ) -> None:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return
        targets = []
        for row in campaign["targets"]:
            if row["target"] == target:
                targets.append({"target": target, "status": status, "scan_id": scan_id})
            else:
                targets.append(row)
        with self.connect() as db:
            db.execute("UPDATE campaigns SET targets_json=? WHERE id=?", (json.dumps(targets), campaign_id))

    @staticmethod
    def _campaign_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "name": row["name"], "status": row["status"], "profile": row["profile"],
            "concurrency": row["concurrency"], "options": json.loads(row["options_json"] or "{}"),
            "targets": json.loads(row["targets_json"] or "[]"), "created_at": row["created_at"],
            "finished_at": row["finished_at"],
        }
