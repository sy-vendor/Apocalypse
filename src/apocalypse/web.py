from __future__ import annotations

import asyncio
import json
import secrets
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
from urllib.parse import parse_qs, urlsplit

from .campaign import CampaignSpec, create_campaign, run_campaign
from .engine import PROFILES, ScanEngine, validate_custom_headers
from .login import example_login_flow, parse_login_flow_document, record_login_interactively
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
                if not self._auth("viewer"):
                    return
                return self._json(storage.dashboard())
            if path == "/api/scans":
                user = self._auth("viewer")
                if not user:
                    return
                tenant = None if user["role"] == "admin" and user.get("tenant_id") == "default" else user.get("tenant_id")
                return self._json({"scans": storage.list_scans(tenant_id=tenant)})
            if path == "/api/findings":
                if not self._auth("viewer"):
                    return
                return self._json({"findings": storage.list_findings()})
            if path == "/api/login-flows":
                if not self._auth("viewer"):
                    return
                return self._json({"flows": storage.list_login_flows(), "template": example_login_flow()})
            if path.startswith("/api/login-record/"):
                if not self._auth("analyst"):
                    return
                session = RECORDING_SESSIONS.get(path.rsplit("/", 1)[-1])
                return self._json(session or {"error": "not found"}, 200 if session else 404)
            if path == "/api/users":
                user = self._auth("admin")
                if not user:
                    return
                return self._json({
                    "users": storage.list_users(),
                    "tenants": storage.list_tenants(),
                    "auth_required": storage.user_count() > 0,
                    "sso": storage.get_sso_config(),
                })
            if path == "/api/tickets":
                if not self._auth("viewer"):
                    return
                return self._json({"tickets": storage.list_tickets(), "config": storage.get_ticket_config()})
            if path == "/api/campaigns":
                if not self._auth("viewer"):
                    return
                return self._json({"campaigns": storage.list_campaigns()})
            if path.startswith("/api/campaigns/"):
                if not self._auth("viewer"):
                    return
                campaign = storage.get_campaign(path.rsplit("/", 1)[-1])
                return self._json(campaign or {"error": "not found"}, 200 if campaign else 404)
            if path.startswith("/api/scans/"):
                if not self._auth("viewer"):
                    return
                scan = storage.get_scan(path.rsplit("/", 1)[-1])
                return self._json(scan or {"error": "scan not found"}, 200 if scan else 404)
            if path.startswith("/reports/") and ".html" in path:
                if not self._auth("viewer"):
                    return
                report_path = urlsplit(self.path).path
                scan_id = report_path.rsplit("/", 1)[-1].split(".html", 1)[0]
                scan = storage.get_scan(scan_id)
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
                    if not self._auth("analyst"):
                        return
                    return self._start_scan()
                if path == "/api/login-flows":
                    if not self._auth("analyst"):
                        return
                    return self._save_login_flow()
                if path == "/api/login-record":
                    if not self._auth("analyst"):
                        return
                    return self._start_login_record()
                if path == "/api/users":
                    # Bootstrap first admin without auth; afterward admin-only.
                    if storage.user_count() > 0 and not self._auth("admin"):
                        return
                    return self._create_user()
                if path == "/api/tenants":
                    if not self._auth("admin"):
                        return
                    return self._create_tenant()
                if path == "/api/sso/config":
                    if not self._auth("admin"):
                        return
                    return self._set_sso_config()
                if path == "/api/sso/login":
                    return self._sso_login()
                if path == "/api/tickets/config":
                    if not self._auth("admin"):
                        return
                    return self._set_ticket_config()
                if path == "/api/tickets":
                    if not self._auth("analyst"):
                        return
                    return self._create_ticket()
                if path.endswith("/sync") and path.startswith("/api/tickets/"):
                    if not self._auth("analyst"):
                        return
                    return self._sync_ticket(path.split("/")[3])
                if path == "/api/campaigns":
                    if not self._auth("analyst"):
                        return
                    return self._create_campaign()
                if path.endswith("/run") and path.startswith("/api/campaigns/"):
                    if not self._auth("analyst"):
                        return
                    return self._run_campaign(path.split("/")[3])
                return self.send_error(404)
            except (ValueError, ScopeError, json.JSONDecodeError, KeyError) as exc:
                return self._json({"error": str(exc)}, 400)

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path.startswith("/api/login-flows/"):
                if not self._auth("analyst"):
                    return
                ok = storage.delete_login_flow(path.rsplit("/", 1)[-1])
                return self._json({"ok": ok}, 200 if ok else 404)
            if path.startswith("/api/scans/"):
                if not self._auth("analyst"):
                    return
                ok = storage.delete_scan(path.rsplit("/", 1)[-1])
                return self._json({"ok": ok}, 200 if ok else 404)
            self.send_error(404)

        def _start_scan(self) -> None:
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
            if policy_doc is not None:
                parse_policy_document(policy_doc if isinstance(policy_doc, dict) else {})
            options = ScanOptions(
                custom_headers=validate_custom_headers(raw_headers),
                submit_forms=submit_forms,
                openapi_url=openapi_url,
                browser_crawl=browser_crawl or bool(login_flow_id),
                graphql=graphql,
                graphql_url=graphql_url,
                webhook_url=validate_webhook_url(webhook_url),
                blind_inject=blind_inject,
                login_flow_id=login_flow_id,
                api_probe=api_probe,
                oast_base_url=validate_oast_base(oast_url),
                oast_listen=oast_listen,
                secondary_headers=validate_custom_headers(raw_secondary or {}),
                browser_verify=browser_verify,
                policy=policy_doc if isinstance(policy_doc, dict) else None,
            )
            if urlsplit(target).scheme not in {"http", "https"} or not urlsplit(target).hostname:
                return self._json({"error": "target must be a complete http(s) URL"}, 400)
            user = self._auth("analyst") or {"tenant_id": "default"}
            result = engine.queue(target, profile, tenant_id=str(user.get("tenant_id") or "default"))

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

        def _start_login_record(self) -> None:
            payload = self._read_json()
            start_url = str(payload.get("start_url", "")).strip()
            timeout_seconds = int(payload.get("timeout_seconds") or 300)
            name = str(payload.get("name", "")).strip() or "recorded-login"
            if urlsplit(start_url).scheme not in {"http", "https"} or not urlsplit(start_url).hostname:
                raise ValueError("start_url must be a complete http(s) URL")
            session_id = secrets.token_hex(6)
            RECORDING_SESSIONS[session_id] = {
                "id": session_id,
                "status": "recording",
                "start_url": start_url,
                "name": name,
                "flow": None,
                "error": None,
                "created_at": now_iso(),
            }

            def worker() -> None:
                try:
                    document = asyncio.run(record_login_interactively(
                        start_url, timeout_seconds=timeout_seconds, headed=True,
                    ))
                    item = {
                        "id": secrets.token_hex(6),
                        "name": name[:80],
                        "flow": document,
                        "created_at": now_iso(),
                        "updated_at": now_iso(),
                    }
                    storage.save_login_flow(item)
                    RECORDING_SESSIONS[session_id].update({
                        "status": "completed", "flow": document, "login_flow_id": item["id"],
                    })
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
            payload = self._read_json()
            row = storage.get_sso_config()
            if not row:
                raise ValueError("SSO is not configured")
            config = row["config"]
            tenant_id = str(payload.get("tenant_id") or "default")
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
                record, token = create_user_record(
                    claims["name"], role,
                    tenant_id=str(saved.get("tenant_id") or "default"),
                    sso_subject=claims["subject"],
                )
                record["created_at"] = now_iso()
                storage.create_user(record)
                user_id, name, tenant_id = record["id"], record["name"], record["tenant_id"]
            html = (
                "<!doctype html><meta charset=utf-8><title>Apocalypse SSO</title>"
                "<body style='font:14px/1.5 system-ui;padding:40px'>"
                f"<h1>Signed in as {name}</h1>"
                f"<p>Role: {role} · Tenant: {tenant_id} · User: {user_id}</p>"
                "<p>Copy this API token into the console (shown once):</p>"
                f"<pre style='background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;"
                f"word-break:break-all'>{token}</pre>"
                "<p><a href='/'>Return to console</a></p></body>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html)

        def _save_login_flow(self) -> None:
            payload = self._read_json()
            name = str(payload.get("name", "")).strip() or "login-flow"
            flow = payload.get("flow")
            if not isinstance(flow, dict):
                raise ValueError("flow must be an object")
            parse_login_flow_document(flow, expand_secrets=False)
            item = {
                "id": str(payload.get("id") or secrets.token_hex(6)),
                "name": name[:80],
                "flow": flow,
                "created_at": now_iso(),
                "updated_at": now_iso(),
            }
            existing = storage.get_login_flow(item["id"])
            if existing:
                item["created_at"] = existing["created_at"]
            storage.save_login_flow(item)
            return self._json(item, HTTPStatus.CREATED)

        def _create_user(self) -> None:
            payload = self._read_json()
            role = str(payload.get("role", "analyst"))
            if storage.user_count() == 0:
                role = "admin"
            tenant_id = str(payload.get("tenant_id") or "default")
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

        def _create_ticket(self) -> None:
            payload = self._read_json()
            scan_id = str(payload.get("scan_id", "")).strip()
            finding_id = payload.get("finding_id")
            scan = storage.get_scan(scan_id)
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

        def _sync_ticket(self, ticket_id: str) -> None:
            ticket = storage.get_ticket(ticket_id)
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

        def _create_campaign(self) -> None:
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
            )
            item = create_campaign(storage, spec)
            return self._json(item, HTTPStatus.CREATED)

        def _run_campaign(self, campaign_id: str) -> None:
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
