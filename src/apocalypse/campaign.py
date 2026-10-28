from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .engine import PROFILES, ScanEngine
from .models import ScanOptions, now_iso
from .storage import Storage
from .webhook import validate_webhook_url


@dataclass(slots=True)
class CampaignSpec:
    name: str
    targets: list[str]
    profile: str = "safe"
    concurrency: int = 2
    allow_private: bool = False
    browser_crawl: bool = False
    graphql: bool = False
    openapi_url: str | None = None
    webhook_url: str | None = None
    blind_inject: bool = False
    submit_forms: bool = False


def validate_targets(targets: list[str]) -> list[str]:
    if not targets:
        raise ValueError("campaign requires at least one target")
    if len(targets) > 100:
        raise ValueError("campaign allows at most 100 targets")
    cleaned: list[str] = []
    for raw in targets:
        target = str(raw).strip()
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"invalid campaign target: {raw}")
        cleaned.append(target)
    return list(dict.fromkeys(cleaned))


def create_campaign(storage: Storage, spec: CampaignSpec) -> dict[str, Any]:
    if spec.profile not in PROFILES:
        raise ValueError("unknown scan profile")
    if not 1 <= spec.concurrency <= 8:
        raise ValueError("concurrency must be between 1 and 8")
    if spec.blind_inject and spec.profile != "deep":
        raise ValueError("blind injection requires the deep profile")
    if spec.submit_forms and spec.profile != "deep":
        raise ValueError("form submission requires the deep profile")
    targets = validate_targets(spec.targets)
    item = {
        "id": secrets.token_hex(6),
        "name": spec.name.strip() or "campaign",
        "status": "queued",
        "profile": spec.profile,
        "concurrency": spec.concurrency,
        "created_at": now_iso(),
        "finished_at": None,
        "options": {
            "allow_private": spec.allow_private,
            "browser_crawl": spec.browser_crawl,
            "graphql": spec.graphql,
            "openapi_url": spec.openapi_url,
            "webhook_url": validate_webhook_url(spec.webhook_url),
            "blind_inject": spec.blind_inject,
            "submit_forms": spec.submit_forms,
        },
        "targets": [{"target": target, "status": "queued", "scan_id": None} for target in targets],
    }
    storage.create_campaign(item)
    return item


async def run_campaign(storage: Storage, engine: ScanEngine, campaign_id: str) -> dict[str, Any]:
    campaign = storage.get_campaign(campaign_id)
    if not campaign:
        raise ValueError(f"campaign not found: {campaign_id}")
    if campaign["status"] == "running":
        raise ValueError("campaign is already running")
    options_raw = campaign.get("options") or {}
    concurrency = max(1, min(8, int(campaign.get("concurrency") or 1)))
    semaphore = asyncio.Semaphore(concurrency)
    storage.update_campaign_status(campaign_id, "running", finished_at=None)

    async def one(target_row: dict[str, Any]) -> None:
        target = target_row["target"]
        async with semaphore:
            storage.update_campaign_target(campaign_id, target, status="running", scan_id=None)
            result = engine.queue(target, campaign["profile"])
            storage.update_campaign_target(campaign_id, target, status="running", scan_id=result.scan_id)
            options = ScanOptions(
                openapi_url=options_raw.get("openapi_url"),
                browser_crawl=bool(options_raw.get("browser_crawl")),
                graphql=bool(options_raw.get("graphql")),
                webhook_url=options_raw.get("webhook_url"),
                blind_inject=bool(options_raw.get("blind_inject")),
                submit_forms=bool(options_raw.get("submit_forms")),
            )
            try:
                await engine.run(
                    result,
                    allow_private=bool(options_raw.get("allow_private")),
                    options=options,
                )
                status = "completed" if result.status == "completed" else "failed"
            except Exception:
                status = "failed"
            storage.update_campaign_target(campaign_id, target, status=status, scan_id=result.scan_id)

    await asyncio.gather(*(one(row) for row in campaign["targets"]))
    refreshed = storage.get_campaign(campaign_id)
    assert refreshed is not None
    failed = sum(1 for row in refreshed["targets"] if row["status"] == "failed")
    final = "failed" if failed and failed == len(refreshed["targets"]) else "completed"
    storage.update_campaign_status(campaign_id, final, finished_at=now_iso())
    return storage.get_campaign(campaign_id) or refreshed
