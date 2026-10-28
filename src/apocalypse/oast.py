"""Minimal out-of-band interaction tracker for authorized blind SSRF / XSS corroboration.

Supports:
- in-memory hits (tests / local listener)
- optional HTTP listener bound to loopback for lab scans
- optional remote poll base (`{base}/poll/{token}`) for deployed collaborators
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx


@dataclass(slots=True)
class OastToken:
    id: str
    http_url: str
    kind: str = "generic"


@dataclass(slots=True)
class OastHit:
    token_id: str
    method: str
    path: str
    remote: str
    headers: dict[str, str] = field(default_factory=dict)


class OastHub:
    def __init__(self, *, public_base: str | None = None, listen: str | None = None):
        self._hits: dict[str, list[OastHit]] = {}
        self._lock = threading.Lock()
        self.public_base = public_base.rstrip("/") if public_base else None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.listen_url: str | None = None
        if listen:
            self._start_listener(listen)

    def _start_listener(self, listen: str) -> None:
        host, _, port_raw = listen.partition(":")
        host = host or "127.0.0.1"
        port = int(port_raw or "0")
        hub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
                return

            def _capture(self) -> None:
                token = self.path.strip("/").split("/", 1)[0]
                if not token:
                    self.send_response(404)
                    self.end_headers()
                    return
                headers = {k.lower(): v for k, v in self.headers.items()}
                hub.record_hit(OastHit(
                    token_id=token, method=self.command, path=self.path,
                    remote=self.client_address[0], headers=headers,
                ))
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                self._capture()

            def do_POST(self) -> None:  # noqa: N802
                length = min(int(self.headers.get("content-length", "0")), 65_536)
                if length:
                    self.rfile.read(length)
                self._capture()

            def do_HEAD(self) -> None:  # noqa: N802
                self._capture()

        server = ThreadingHTTPServer((host, port), Handler)
        self._server = server
        bound_host, bound_port = server.server_address[0], server.server_address[1]
        self.listen_url = f"http://{bound_host}:{bound_port}"
        self._thread = threading.Thread(target=server.serve_forever, name="apocalypse-oast", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def enabled(self) -> bool:
        return bool(self.public_base or self.listen_url)

    def issue(self, kind: str = "generic") -> OastToken:
        token_id = secrets.token_hex(8)
        base = self.public_base or self.listen_url
        if not base:
            # Placeholder that will not verify; callers should skip verified OAST findings.
            http_url = f"http://oast.invalid/{token_id}"
        else:
            http_url = f"{base.rstrip('/')}/{token_id}"
        with self._lock:
            self._hits.setdefault(token_id, [])
        return OastToken(id=token_id, http_url=http_url, kind=kind)

    def record_hit(self, hit: OastHit) -> None:
        with self._lock:
            self._hits.setdefault(hit.token_id, []).append(hit)

    def local_hits(self, token_id: str) -> list[OastHit]:
        with self._lock:
            return list(self._hits.get(token_id, []))

    async def poll(self, token: OastToken) -> list[dict[str, Any]]:
        local = [
            {"method": hit.method, "path": hit.path, "remote": hit.remote}
            for hit in self.local_hits(token.id)
        ]
        if local:
            return local
        if not self.public_base:
            return []
        url = f"{self.public_base}/poll/{token.id}"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(url, headers={"Accept": "application/json"})
                if response.status_code >= 400:
                    return []
                payload = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            interactions = payload.get("interactions") or payload.get("hits") or []
            return [item for item in interactions if isinstance(item, dict)]
        return []

    async def confirmed(self, token: OastToken) -> bool:
        return bool(await self.poll(token))


def validate_oast_base(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("oast base must be an absolute http(s) URL")
    return url.strip().rstrip("/")
