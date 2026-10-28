from __future__ import annotations

import asyncio
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .engine import ScanEngine
from .models import ScanOptions, now_iso
from .storage import Storage
from .webhook import validate_webhook_url


def next_run_at(interval_minutes: int, *, from_time: datetime | None = None) -> str:
    base = from_time or datetime.now(timezone.utc)
    return (base + timedelta(minutes=interval_minutes)).isoformat()


def create_schedule(
    storage: Storage,
    *,
    target: str,
    profile: str,
    interval_minutes: int,
    allow_private: bool = False,
    openapi_url: str | None = None,
    browser_crawl: bool = False,
    graphql: bool = False,
    graphql_url: str | None = None,
    webhook_url: str | None = None,
) -> dict[str, Any]:
    if interval_minutes < 5 or interval_minutes > 60 * 24 * 30:
        raise ValueError("interval_minutes must be between 5 and 43200")
    item = {
        "id": secrets.token_hex(6),
        "target": target,
        "profile": profile,
        "interval_minutes": interval_minutes,
        "enabled": True,
        "allow_private": allow_private,
        "openapi_url": openapi_url,
        "browser_crawl": browser_crawl,
        "graphql": graphql,
        "graphql_url": graphql_url,
        "webhook_url": validate_webhook_url(webhook_url),
        "created_at": now_iso(),
        "next_run_at": next_run_at(interval_minutes),
    }
    storage.create_schedule(item)
    return item


def run_due_schedules(storage: Storage, engine: ScanEngine) -> list[str]:
    """Execute due schedules synchronously; intended for the console background worker."""
    started: list[str] = []
    now = now_iso()
    for item in storage.due_schedules(now):
        options = ScanOptions(
            openapi_url=item.get("openapi_url") or None,
            browser_crawl=bool(item.get("browser_crawl")),
            graphql=bool(item.get("graphql")),
            graphql_url=item.get("graphql_url") or None,
            webhook_url=item.get("webhook_url") or None,
        )
        result = engine.queue(
            item["target"], item["profile"], tenant_id=str(item.get("tenant_id") or "default"),
        )
        asyncio.run(engine.run(result, allow_private=bool(item.get("allow_private")), options=options))
        storage.mark_schedule_run(
            item["id"],
            next_run_at=next_run_at(int(item["interval_minutes"])),
            last_run_at=now_iso(),
            last_scan_id=result.scan_id,
        )
        started.append(result.scan_id)
    return started


def start_scheduler(storage: Storage, engine: ScanEngine, *, interval_seconds: int = 30) -> threading.Thread:
    def loop() -> None:
        while True:
            try:
                run_due_schedules(storage, engine)
            except Exception as exc:  # noqa: BLE001 - keep scheduler alive
                print(f"[schedule] {type(exc).__name__}: {exc}")
            time.sleep(interval_seconds)

    thread = threading.Thread(target=loop, name="apocalypse-scheduler", daemon=True)
    thread.start()
    return thread
