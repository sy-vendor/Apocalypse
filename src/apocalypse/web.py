from __future__ import annotations

import asyncio
import html
import json
import os
import re
import subprocess
import secrets
import sys
import threading
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .campaign import CampaignSpec, create_campaign, run_campaign
from .engine import PROFILES, ScanEngine, validate_custom_headers
from .login import (
    example_login_flow,
    normalize_login_secrets,
    parse_login_flow_document,
    record_login_interactively,
)
from .models import ScanOptions, now_iso
from .reporting import lang_from_request, render_html
from .scope import ScopeError
from .sso import (
    build_authorize_url, discover_oidc, exchange_code_for_claims, new_sso_state, tenant_slug,
    validate_oidc_config,
)
from .storage import Storage
from .team import create_user_record, hash_token, issue_token, role_allows
from .oast import validate_oast_base
from .policy import parse_policy_document
from .tickets import create_external_ticket, finding_ticket_key, sync_external_ticket, validate_ticket_config
from .webhook import validate_webhook_url


STATIC = Path(__file__).with_name("static")
RECORDING_SESSIONS: dict[str, dict] = {}
RECORDING_SESSION_TTL = timedelta(hours=1)
QUALITY_STATE: dict[str, object] = {"status": "idle", "error": None}
QUALITY_LOCK = threading.Lock()


def _benchmark_root() -> Path | None:
    candidates = [Path(__file__).resolve().parents[2] / "benchmark", Path.cwd() / "benchmark"]
    return next((path for path in candidates if (path / "run_lab.py").is_file()), None)


def _tenant_scope(user: dict | None) -> str | None:
    """Return tenant filter for storage queries.

    Platform admins bound to the default tenant may see all tenants (None).
    Everyone else is hard-scoped to their own tenant_id.
    """
    if not user:
        return "default"
    if user.get("role") == "admin" and user.get("tenant_id") == "default":
        return None
    return str(user.get("tenant_id") or "default")


def _purge_recording_sessions() -> None:
    cutoff = datetime.now(timezone.utc) - RECORDING_SESSION_TTL
    expired = []
    for session_id, item in RECORDING_SESSIONS.items():
        created = item.get("created_at")
        try:
            stamp = datetime.fromisoformat(str(created)) if created else None
            if stamp and stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        except ValueError:
            stamp = None
        if stamp is None or stamp < cutoff:
            expired.append(session_id)
    for session_id in expired:
        RECORDING_SESSIONS.pop(session_id, None)


def _load_ci_quality_summary(root: Path | None) -> dict:
    """Prefer a versioned CI/local artifact; fall back to unavailable rather than inventing freshness."""
    candidates: list[Path] = []
    if root:
        candidates.extend([
            root / "results" / "ci-summary.json",
            root / "results" / "quality-summary.json",
        ])
    candidates.append(Path.cwd() / "benchmark" / "results" / "ci-summary.json")
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload.setdefault("source", str(path))
                payload.setdefault("stale", False)
                return payload
        except (OSError, ValueError, TypeError):
            continue
    coverage_path = Path.cwd() / "coverage.xml"
    coverage = None
    if coverage_path.is_file():
        try:
            text = coverage_path.read_text(encoding="utf-8", errors="ignore")
            # coverage.py XML: line-rate="0.47"
            match = re.search(r'line-rate="([0-9.]+)"', text)
            if match:
                coverage = {"percent": round(float(match.group(1)) * 100), "gate": 45, "source": str(coverage_path)}
        except (OSError, ValueError):
            coverage = None
    return {
        "tests": None,
        "coverage": coverage,
        "stale": True,
        "source": None,
        "note": "No CI quality summary artifact found; coverage shown only if coverage.xml exists locally.",
    }


def quality_snapshot() -> dict:
    root = _benchmark_root()
    summary = _load_ci_quality_summary(root)
    payload: dict = {
        "tests": summary.get("tests"),
        "coverage": summary.get("coverage"),
        "quality_meta": {
            "stale": bool(summary.get("stale", True)),
            "source": summary.get("source"),
            "note": summary.get("note"),
        },
        "runner_available": root is not None,
        "run": dict(QUALITY_STATE),
        "ground_truth": {},
        "benchmark": None,
    }
    if root:
        try:
            truth = json.loads((root / "ground_truth.json").read_text(encoding="utf-8"))
            cases = truth.get("cases") or []
            payload["ground_truth"] = {
                "version": truth.get("version"),
                "cases": len(cases),
                "positives": sum(case.get("expected") == "positive" for case in cases),
                "negatives": sum(case.get("expected") == "negative" for case in cases),
                "families": len({case.get("family") for case in cases}),
                "human_signoff": (truth.get("curation") or {}).get("human_signoff", "pending"),
            }
        except (OSError, ValueError, TypeError):
            payload["ground_truth"] = {"error": "ground truth unavailable"}
        result_path = root / "results" / "latest.json"
        try:
            payload["benchmark"] = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            pass
    return payload


def start_quality_benchmark() -> bool:
    root = _benchmark_root()
    if root is None:
        raise ValueError("benchmark runner is unavailable in this installation")
    with QUALITY_LOCK:
        if QUALITY_STATE.get("status") == "running":
            return False
        QUALITY_STATE.update({
            "status": "running", "error": None, "started_at": now_iso(), "finished_at": None,
        })

    def worker() -> None:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed local script and argv, no shell
                [sys.executable, str(root / "run_lab.py"), "--min-recall", "1.0", "--min-precision", "1.0"],
                cwd=root.parent, capture_output=True, text=True, timeout=600, check=False,
            )
            error = None if completed.returncode == 0 else (completed.stderr.strip() or completed.stdout[-1000:])
            QUALITY_STATE.update({
                "status": "completed" if completed.returncode == 0 else "failed",
                "error": error, "finished_at": now_iso(),
            })
        except (OSError, subprocess.SubprocessError) as exc:
            QUALITY_STATE.update({"status": "failed", "error": str(exc), "finished_at": now_iso()})

    threading.Thread(target=worker, name="quality-benchmark", daemon=True).start()
    return True


def _optional_str(value: object) -> str | None:
    """Coerce JSON optional strings; avoid str(None) -> 'None'."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "undefined"}:
        return None
    return text


def make_handler(storage: Storage, engine: ScanEngine) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "ApocalypseUI/0.10"

        def log_message(self, fmt: str, *args: object) -> None:
            print(f"[web] {self.address_string()} {fmt % args}")

        def _json(self, payload: object, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path, content_type: str) -> None:
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self, limit: int = 65_536) -> dict:
            length = min(int(self.headers.get("content-length", "0")), limit)
            return json.loads(self.rfile.read(length) or b"{}")

        def _auth(self, minimum: str = "viewer") -> dict | None:
            if storage.user_count() == 0:
                return {"id": "local", "name": "local", "role": "admin", "tenant_id": "default"}
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                self._json({"error": "authentication required"}, 401)
                return None
            user = storage.authenticate_token(header[7:].strip())
            if not user or not role_allows(user["role"], minimum):
                self._json({"error": "forbidden"}, 403)
                return None
            user.setdefault("tenant_id", "default")
            return user

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            query = parse_qs(urlsplit(self.path).query)
            if path == "/":
                return self._file(STATIC / "index.html", "text/html; charset=utf-8")
            if path == "/app.js":
                return self._file(STATIC / "app.js", "text/javascript; charset=utf-8")
            if path == "/styles.css":
                return self._file(STATIC / "styles.css", "text/css; charset=utf-8")
            if path == "/api/sso/callback":
                return self._sso_callback(query)
            if path == "/api/dashboard":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json(storage.dashboard(tenant_id=_tenant_scope(user)))
            if path == "/api/quality":
                if not self._auth("viewer"):
                    return
                return self._json(quality_snapshot())
            if path == "/api/scans":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json({"scans": storage.list_scans(tenant_id=_tenant_scope(user))})
            if path == "/api/findings":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json({"findings": storage.list_findings(tenant_id=_tenant_scope(user))})
            if path == "/api/login-flows":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json({
                    "flows": storage.list_login_flows(tenant_id=_tenant_scope(user)),
                    "template": example_login_flow(),
                })
            if path.startswith("/api/login-record/"):
                user = self._auth("analyst")
                if not user:
                    return
                _purge_recording_sessions()
                session = RECORDING_SESSIONS.get(path.rsplit("/", 1)[-1])
                if not session:
                    return self._json({"error": "not found"}, 404)
                scope = _tenant_scope(user)
                if scope is not None and session.get("tenant_id") != scope:
                    return self._json({"error": "not found"}, 404)
                return self._json(session)
            if path == "/api/users":
                user = self._auth("admin")
                if not user:
                    return
                scope = _tenant_scope(user)
                return self._json({
                    "users": storage.list_users(tenant_id=scope),
                    "tenants": storage.list_tenants() if scope is None else [
                        item for item in storage.list_tenants() if item.get("id") == scope
                    ],
                    "auth_required": storage.user_count() > 0,
                    "sso": storage.get_sso_config() if scope is None else None,
                })
            if path == "/api/tickets":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json({
                    "tickets": storage.list_tickets(tenant_id=_tenant_scope(user)),
                    "config": storage.get_ticket_config(),
                })
            if path == "/api/campaigns":
                user = self._auth("viewer")
                if not user:
                    return
                return self._json({"campaigns": storage.list_campaigns(tenant_id=_tenant_scope(user))})
            if path.startswith("/api/campaigns/"):
                user = self._auth("viewer")
                if not user:
                    return
                campaign = storage.get_campaign(path.rsplit("/", 1)[-1], tenant_id=_tenant_scope(user))
                return self._json(campaign or {"error": "not found"}, 200 if campaign else 404)
            if path.startswith("/api/scans/"):
                user = self._auth("viewer")
                if not user:
                    return
                scan = storage.get_scan(path.rsplit("/", 1)[-1], tenant_id=_tenant_scope(user))
                return self._json(scan or {"error": "scan not found"}, 200 if scan else 404)
            if path.startswith("/reports/") and ".html" in path:
                user = self._auth("viewer")
                if not user:
                    return
                report_path = urlsplit(self.path).path
                scan_id = report_path.rsplit("/", 1)[-1].split(".html", 1)[0]
                scan = storage.get_scan(scan_id, tenant_id=_tenant_scope(user))
                if not scan:
                    return self.send_error(404)
                lang = lang_from_request(self.path, self.headers.get("Accept-Language"))
                body = render_html(scan, lang=lang).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return self.wfile.write(body)
            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            try:
                if path == "/api/scans":
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._start_scan(user)
                if path == "/api/quality/run":
                    if not self._auth("admin"):
                        return
                    started = start_quality_benchmark()
                    return self._json(
                        {"status": "running", "started": started},
                        HTTPStatus.ACCEPTED if started else HTTPStatus.OK,
                    )
                if path == "/api/login-flows":
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._save_login_flow(user)
                if path == "/api/login-record":
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._start_login_record(user)
                if path == "/api/users":
                    # Bootstrap first admin without auth; afterward admin-only.
                    user = None
                    if storage.user_count() > 0:
                        user = self._auth("admin")
                        if not user:
                            return
                    return self._create_user(user)
                if path == "/api/tenants":
                    user = self._auth("admin")
                    if not user:
                        return
                    if _tenant_scope(user) is not None:
                        return self._json({"error": "only the platform admin may create tenants"}, 403)
                    return self._create_tenant()
                if path == "/api/sso/config":
                    user = self._auth("admin")
                    if not user:
                        return
                    if _tenant_scope(user) is not None:
                        return self._json({"error": "only the platform admin may configure SSO"}, 403)
                    return self._set_sso_config()
                if path == "/api/sso/login":
                    return self._sso_login()
                if path == "/api/tickets/config":
                    user = self._auth("admin")
                    if not user:
                        return
                    if _tenant_scope(user) is not None:
                        return self._json({"error": "only the platform admin may configure tickets"}, 403)
                    return self._set_ticket_config()
                if path == "/api/tickets":
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._create_ticket(user)
                if path.endswith("/sync") and path.startswith("/api/tickets/"):
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._sync_ticket(path.split("/")[3], user)
                if path == "/api/campaigns":
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._create_campaign(user)
                if path.endswith("/run") and path.startswith("/api/campaigns/"):
                    user = self._auth("analyst")
                    if not user:
                        return
                    return self._run_campaign(path.split("/")[3], user)
                return self.send_error(404)
            except (ValueError, ScopeError, json.JSONDecodeError, KeyError) as exc:
                return self._json({"error": str(exc)}, 400)

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path.startswith("/api/login-flows/"):
                user = self._auth("analyst")
                if not user:
                    return
                ok = storage.delete_login_flow(path.rsplit("/", 1)[-1], tenant_id=_tenant_scope(user))
                return self._json({"ok": ok}, 200 if ok else 404)
            if path.startswith("/api/scans/"):
                user = self._auth("analyst")
                if not user:
                    return
                ok = storage.delete_scan(path.rsplit("/", 1)[-1], tenant_id=_tenant_scope(user))
                return self._json({"ok": ok}, 200 if ok else 404)
            self.send_error(404)

        def _start_scan(self, user: dict) -> None:
            payload = self._read_json()
            target = str(payload.get("target", "")).strip()
            profile = str(payload.get("profile", "safe"))
            acknowledged = payload.get("acknowledged") is True
            allow_private = payload.get("allow_private") is True
            submit_forms = payload.get("submit_forms") is True
            blind_inject = payload.get("blind_inject") is True
            raw_headers = payload.get("custom_headers", {})
            openapi_url = _optional_str(payload.get("openapi_url"))
            browser_crawl = payload.get("browser_crawl") is True
            graphql = payload.get("graphql") is True
            graphql_url = _optional_str(payload.get("graphql_url"))
            webhook_url = _optional_str(payload.get("webhook_url"))
            login_flow_id = _optional_str(payload.get("login_flow_id"))
            login_password = _optional_str(payload.get("login_password"))
            api_probe = payload.get("api_probe", True) is not False
            oast_url = _optional_str(payload.get("oast_url"))
            oast_listen = _optional_str(payload.get("oast_listen"))
            browser_verify = payload.get("browser_verify") is True
            raw_secondary = payload.get("secondary_headers", {})
            policy_doc = payload.get("policy")
            if not acknowledged:
                return self._json({"error": "authorization acknowledgement is required"}, 400)
            if profile not in PROFILES:
                return self._json({"error": "unknown scan profile"}, 400)
            if submit_forms and profile != "deep":
                return self._json({"error": "form submission requires the deep profile"}, 400)
            if blind_inject and profile != "deep":
                return self._json({"error": "blind injection requires the deep profile"}, 400)
            if oast_url and oast_listen:
                return self._json({"error": "use either oast_url or oast_listen, not both"}, 400)
            if not isinstance(raw_headers, dict):
                return self._json({"error": "custom_headers must be an object"}, 400)
            if raw_secondary and not isinstance(raw_secondary, dict):
                return self._json({"error": "secondary_headers must be an object"}, 400)
            try:
                login_secrets = normalize_login_secrets(
                    payload.get("login_secrets"),
                    login_password=login_password,
                )
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            if policy_doc is not None:
                parse_policy_document(policy_doc if isinstance(policy_doc, dict) else {})
            tenant_id = str(user.get("tenant_id") or "default")
            if login_flow_id and not storage.get_login_flow(login_flow_id, tenant_id=tenant_id):
                return self._json({"error": "login flow not found"}, 404)
            options = ScanOptions(
                custom_headers=validate_custom_headers(raw_headers),
                submit_forms=submit_forms,
                openapi_url=openapi_url,
                browser_crawl=browser_crawl or bool(login_flow_id),
                graphql=graphql,
                graphql_url=graphql_url,
                webhook_url=validate_webhook_url(webhook_url, allow_private=allow_private),
                blind_inject=blind_inject,
                login_flow_id=login_flow_id,
                login_secrets=login_secrets,
                api_probe=api_probe,
                oast_base_url=validate_oast_base(oast_url),
                oast_listen=oast_listen,
                secondary_headers=validate_custom_headers(raw_secondary or {}),
                browser_verify=browser_verify,
                policy=policy_doc if isinstance(policy_doc, dict) else None,
            )
            if urlsplit(target).scheme not in {"http", "https"} or not urlsplit(target).hostname:
                return self._json({"error": "target must be a complete http(s) URL"}, 400)
            result = engine.queue(target, profile, tenant_id=tenant_id)

            def _run_scan() -> None:
                try:
                    asyncio.run(engine.run(result, allow_private=allow_private, options=options))
                except Exception as exc:  # noqa: BLE001 — keep UI status out of "queued" forever
                    result.errors.append(f"fatal: {type(exc).__name__}: {exc}")
                    result.status = "failed"
                    result.finished_at = now_iso()
                    storage.update_scan(result)

            thread = threading.Thread(target=_run_scan, name=f"scan-{result.scan_id}", daemon=True)
            thread.start()
            return self._json({"scan_id": result.scan_id, "status": "queued"}, HTTPStatus.ACCEPTED)

        def _start_login_record(self, user: dict) -> None:
            payload = self._read_json()
            start_url = str(payload.get("start_url", "")).strip()
            timeout_seconds = int(payload.get("timeout_seconds") or 300)
            # Recording only drafts into the editor; persist via POST /api/login-flows.
            name = (str(payload.get("name", "")).strip() or "recorded-login")[:80]
            if urlsplit(start_url).scheme not in {"http", "https"} or not urlsplit(start_url).hostname:
                raise ValueError("start_url must be a complete http(s) URL")
            _purge_recording_sessions()
            session_id = secrets.token_hex(6)
            RECORDING_SESSIONS[session_id] = {
                "id": session_id,
                "status": "recording",
                "start_url": start_url,
                "name": name,
                "flow": None,
                "error": None,
                "tenant_id": str(user.get("tenant_id") or "default"),
                "created_at": now_iso(),
            }

            def worker() -> None:
                try:
                    document = asyncio.run(record_login_interactively(
                        start_url, timeout_seconds=timeout_seconds, headed=True,
                    ))
                    RECORDING_SESSIONS[session_id].update({"status": "completed", "flow": document})
                except Exception as exc:  # noqa: BLE001 — surface recorder failures to UI
                    RECORDING_SESSIONS[session_id].update({"status": "failed", "error": str(exc)})

            threading.Thread(target=worker, name=f"record-{session_id}", daemon=True).start()
            return self._json({"session_id": session_id, "status": "recording"}, HTTPStatus.ACCEPTED)

        def _create_tenant(self) -> None:
            payload = self._read_json()
            name = str(payload.get("name", "")).strip()
            if not name:
                raise ValueError("tenant name is required")
            slug = tenant_slug(str(payload.get("slug") or name))
            item = {
                "id": secrets.token_hex(6),
                "name": name[:80],
                "slug": slug,
                "created_at": now_iso(),
            }
            storage.create_tenant(item)
            return self._json(item, HTTPStatus.CREATED)

        def _set_sso_config(self) -> None:
            payload = self._read_json()
            config = validate_oidc_config(payload.get("config") or payload)
            storage.set_sso_config(config)
            return self._json({"config": {k: v for k, v in config.items() if k != "client_secret"}})

        def _sso_login(self) -> None:
            # Body may be empty; tenant membership comes from server-side SSO config only.
            try:
                self._read_json()
            except json.JSONDecodeError:
                pass
            row = storage.get_sso_config()
            if not row:
                raise ValueError("SSO is not configured")
            config = row["config"]
            tenant_id = str(config.get("default_tenant_id") or "default")
            state, nonce = new_sso_state()
            storage.save_sso_state(state, nonce, tenant_id)
            discovery = asyncio.run(discover_oidc(config["issuer"]))
            url = build_authorize_url(discovery, config, state=state, nonce=nonce)
            return self._json({"authorize_url": url, "state": state})

        def _sso_callback(self, query: dict) -> None:
            code = (query.get("code") or [""])[0]
            state = (query.get("state") or [""])[0]
            if not code or not state:
                return self._json({"error": "missing code/state"}, 400)
            saved = storage.consume_sso_state(state)
            if not saved:
                return self._json({"error": "invalid or expired SSO state"}, 400)
            row = storage.get_sso_config()
            if not row:
                return self._json({"error": "SSO is not configured"}, 400)
            config = row["config"]
            secret = os.environ.get(str(config.get("client_secret_env") or "OIDC_CLIENT_SECRET"))
            if not secret:
                return self._json({"error": "OIDC client secret environment variable is unset"}, 400)
            try:
                discovery = asyncio.run(discover_oidc(config["issuer"]))
                claims = asyncio.run(exchange_code_for_claims(
                    discovery, config, code=code, client_secret=secret,
                ))
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": f"SSO exchange failed: {exc}"}, 400)
            existing = storage.find_user_by_sso_subject(claims["subject"])
            if existing:
                token = issue_token()
                with storage.connect() as db:
                    db.execute(
                        "UPDATE users SET token_hash=?, name=? WHERE id=?",
                        (hash_token(token), claims["name"], existing["id"]),
                    )
                user_id = existing["id"]
                role = existing["role"]
                tenant_id = existing.get("tenant_id") or "default"
                name = claims["name"]
            else:
                role = "analyst" if storage.user_count() > 0 else "admin"
                # Prefer SSO-config default (persisted in state); never trust client-supplied IDs.
                provision_tenant = str(
                    saved.get("tenant_id")
                    or config.get("default_tenant_id")
                    or "default"
                )
                record, token = create_user_record(
                    claims["name"], role,
                    tenant_id=provision_tenant,
                    sso_subject=claims["subject"],
                )
                record["created_at"] = now_iso()
                storage.create_user(record)
                user_id, name, tenant_id = record["id"], record["name"], record["tenant_id"]
            safe_name = html.escape(str(name), quote=True)
            safe_role = html.escape(str(role), quote=True)
            safe_tenant = html.escape(str(tenant_id), quote=True)
            safe_user = html.escape(str(user_id), quote=True)
            safe_token = html.escape(str(token), quote=True)
            page = (
                "<!doctype html><meta charset=utf-8><title>Apocalypse SSO</title>"
                "<body style='font:14px/1.5 system-ui;padding:40px'>"
                f"<h1>Signed in as {safe_name}</h1>"
                f"<p>Role: {safe_role} · Tenant: {safe_tenant} · User: {safe_user}</p>"
                "<p>Copy this API token into the console (shown once):</p>"
                f"<pre style='background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;"
                f"word-break:break-all'>{safe_token}</pre>"
                "<p><a href='/'>Return to console</a></p></body>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(page)

        def _save_login_flow(self, user: dict) -> None:
            payload = self._read_json()
            flow = payload.get("flow")
            if not isinstance(flow, dict):
                raise ValueError("flow must be an object")
            parse_login_flow_document(flow, expand_secrets=False)
            tenant_id = str(user.get("tenant_id") or "default")
            item = {
                "id": str(payload.get("id") or secrets.token_hex(6)),
                "tenant_id": tenant_id,
                "name": str(payload.get("name", "")).strip() or "login-flow",
                "flow": flow,
                "created_at": now_iso(),
                "updated_at": now_iso(),
            }
            existing = storage.get_login_flow(item["id"], tenant_id=tenant_id)
            if existing:
                item["created_at"] = existing["created_at"]
                item["name"] = storage.unique_login_flow_name(
                    item["name"], exclude_id=item["id"], tenant_id=tenant_id,
                )[:80]
            else:
                item["name"] = storage.unique_login_flow_name(item["name"], tenant_id=tenant_id)[:80]
            storage.save_login_flow(item)
            return self._json(item, HTTPStatus.CREATED)

        def _create_user(self, actor: dict | None) -> None:
            payload = self._read_json()
            role = str(payload.get("role", "analyst"))
            if storage.user_count() == 0:
                role = "admin"
            scope = _tenant_scope(actor) if actor else None
            if scope is None:
                tenant_id = str(payload.get("tenant_id") or "default")
            else:
                tenant_id = scope
            record, token = create_user_record(str(payload.get("name", "")), role, tenant_id=tenant_id)
            record["created_at"] = now_iso()
            storage.create_user(record)
            return self._json({
                "user": {
                    "id": record["id"], "name": record["name"], "role": record["role"],
                    "tenant_id": record["tenant_id"],
                },
                "token": token,
            }, HTTPStatus.CREATED)

        def _set_ticket_config(self) -> None:
            payload = self._read_json()
            provider = str(payload.get("provider", "")).strip()
            config = validate_ticket_config(provider, payload.get("config") or {})
            storage.set_ticket_config(provider, config)
            return self._json({"provider": provider, "config": config})

        def _create_ticket(self, user: dict) -> None:
            payload = self._read_json()
            scan_id = str(payload.get("scan_id", "")).strip()
            finding_id = payload.get("finding_id")
            tenant_id = _tenant_scope(user)
            scan = storage.get_scan(scan_id, tenant_id=tenant_id)
            if not scan:
                raise ValueError("scan not found")
            findings = scan.get("findings_list") or []
            finding = None
            if finding_id is not None:
                for item in findings:
                    if item.get("id") == finding_id:
                        finding = item
                        break
            elif findings:
                finding = findings[0]
            if not finding:
                raise ValueError("finding not found")
            config_row = storage.get_ticket_config()
            if not config_row:
                raise ValueError("ticket provider is not configured")
            created = asyncio.run(create_external_ticket(
                config_row["provider"], config_row["config"], finding=finding, scan=scan,
            ))
            ticket = {
                "id": secrets.token_hex(6),
                "tenant_id": str(user.get("tenant_id") or "default"),
                "finding_key": finding_ticket_key(scan_id, finding),
                "scan_id": scan_id,
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "provider": config_row["provider"],
                "external_id": created["external_id"],
                "external_url": created["external_url"],
                "status": created["status"],
                "created_at": now_iso(),
                "last_sync_at": created["synced_at"],
                "meta": {},
            }
            storage.upsert_ticket(ticket)
            return self._json(ticket, HTTPStatus.CREATED)

        def _sync_ticket(self, ticket_id: str, user: dict) -> None:
            ticket = storage.get_ticket(ticket_id, tenant_id=_tenant_scope(user))
            if not ticket:
                return self._json({"error": "ticket not found"}, 404)
            config_row = storage.get_ticket_config()
            if not config_row:
                raise ValueError("ticket provider is not configured")
            synced = asyncio.run(sync_external_ticket(config_row["provider"], config_row["config"], ticket))
            ticket["status"] = synced["status"]
            ticket["external_url"] = synced["external_url"]
            ticket["last_sync_at"] = synced["synced_at"]
            ticket["meta"] = synced.get("raw") or {}
            storage.upsert_ticket(ticket)
            return self._json(ticket)

        def _create_campaign(self, user: dict) -> None:
            payload = self._read_json()
            if payload.get("acknowledged") is not True:
                raise ValueError("authorization acknowledgement is required")
            targets = payload.get("targets") or []
            if isinstance(targets, str):
                targets = [line.strip() for line in targets.splitlines() if line.strip()]
            spec = CampaignSpec(
                name=str(payload.get("name") or "campaign"),
                targets=list(targets),
                profile=str(payload.get("profile") or "safe"),
                concurrency=int(payload.get("concurrency") or 2),
                allow_private=payload.get("allow_private") is True,
                browser_crawl=payload.get("browser_crawl") is True,
                graphql=payload.get("graphql") is True,
                openapi_url=str(payload.get("openapi_url") or "").strip() or None,
                webhook_url=str(payload.get("webhook_url") or "").strip() or None,
                blind_inject=payload.get("blind_inject") is True,
                submit_forms=payload.get("submit_forms") is True,
                tenant_id=str(user.get("tenant_id") or "default"),
            )
            item = create_campaign(storage, spec)
            return self._json(item, HTTPStatus.CREATED)

        def _run_campaign(self, campaign_id: str, user: dict) -> None:
            if not storage.get_campaign(campaign_id, tenant_id=_tenant_scope(user)):
                return self._json({"error": "campaign not found"}, 404)
            thread = threading.Thread(
                target=lambda: asyncio.run(run_campaign(storage, engine, campaign_id)),
                name=f"campaign-{campaign_id}", daemon=True,
            )
            thread.start()
            return self._json({"campaign_id": campaign_id, "status": "running"}, HTTPStatus.ACCEPTED)

    return Handler


def serve(
    storage: Storage, engine: ScanEngine, host: str, port: int, *, enable_scheduler: bool = True,
) -> None:
    if enable_scheduler:
        from .schedule import start_scheduler
        start_scheduler(storage, engine)
        print("Apocalypse scheduler enabled")
    server = ThreadingHTTPServer((host, port), make_handler(storage, engine))
    print(f"Apocalypse console: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nApocalypse console stopped")
    finally:
        server.server_close()
