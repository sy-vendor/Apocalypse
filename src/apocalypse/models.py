from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    url: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    category: str = "configuration"
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanStats:
    requests: int = 0
    pages: int = 0
    discovered: int = 0
    discovered_http: int = 0
    discovered_browser: int = 0
    findings: int = 0


@dataclass(slots=True)
class ScanOptions:
    """Ephemeral scan settings. Secrets in custom headers / login values are never persisted."""

    custom_headers: dict[str, str] = field(default_factory=dict)
    submit_forms: bool = False
    openapi_url: str | None = None
    browser_crawl: bool = False
    login_flow_path: str | None = None
    graphql: bool = False
    graphql_url: str | None = None
    webhook_url: str | None = None
    fail_on: str = "none"
    blind_inject: bool = False
    login_flow_id: str | None = None
    login_secrets: dict[str, str] = field(default_factory=dict)
    campaign_id: str | None = None
    api_probe: bool = True
    oast_base_url: str | None = None
    oast_listen: str | None = None
    secondary_headers: dict[str, str] = field(default_factory=dict)
    browser_verify: bool = False
    policy: dict | None = None


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    target: str
    profile: str
    status: str = "queued"
    created_at: str = field(default_factory=now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    stats: ScanStats = field(default_factory=ScanStats)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    baseline: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data

