from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from .models import ScanResult
from .scope import ScopeError, assert_host_allowed, dns_pin, pin_url_for_request


def validate_webhook_url(url: str | None, *, allow_private: bool = False) -> str | None:
    if not url:
        return None
    value = url.strip()
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("webhook URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("credentials in webhook URL are not permitted")
    try:
        assert_host_allowed(
            parsed.hostname,
            allow_private=allow_private,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except ScopeError as exc:
        raise ValueError(str(exc)) from exc
    return value


def scan_webhook_payload(result: ScanResult) -> dict[str, Any]:
    """Build a secret-free completion payload for CI / ticketing integrations."""
    severities: dict[str, int] = {}
    for item in result.findings:
        severities[item.severity] = severities.get(item.severity, 0) + 1
    return {
        "event": "scan.completed",
        "scan_id": result.scan_id,
        "target": result.target,
        "profile": result.profile,
        "status": result.status,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "stats": {
            "requests": result.stats.requests,
            "pages": result.stats.pages,
            "discovered": result.stats.discovered,
            "discovered_http": result.stats.discovered_http,
            "discovered_browser": result.stats.discovered_browser,
            "findings": result.stats.findings,
        },
        "findings_by_severity": severities,
        "baseline": result.baseline or {},
        "error_count": len(result.errors),
        "findings": [
            {
                "rule_id": item.rule_id,
                "title": item.title,
                "severity": item.severity,
                "confidence": item.confidence,
                "url": item.url,
                "category": item.category,
                "verified": item.verified,
            }
            for item in result.findings[:200]
        ],
    }


async def deliver_webhook(url: str, payload: dict[str, Any], *, timeout: float = 10.0) -> None:
    # Re-resolve and pin DNS immediately before connect; keep hostname URL for TLS.
    request_url, host_header, _, connect_ip = pin_url_for_request(url, allow_private=False)
    headers = {
        "User-Agent": "Apocalypse-Webhook/0.6",
        "Host": host_header,
        "Content-Type": "application/json",
    }
    hostname = urlsplit(url).hostname
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, pool=min(10.0, timeout)), follow_redirects=False,
    ) as client:
        with dns_pin(hostname, connect_ip):
            response = await client.post(request_url, json=payload, headers=headers)
            response.raise_for_status()
