from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .scope import ScopePolicy

DEFAULT_USER_AGENT = "Sentinel-SRC/0.1 (authorized security testing)"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    scope: ScopePolicy
    automation_allowed: bool = True
    requests_per_second: float = 2.0
    concurrency: int = 4
    timeout_seconds: float = 10.0
    max_body_bytes: int = 65_536
    user_agent: str = DEFAULT_USER_AGENT
    excluded_finding_ids: tuple[str, ...] = ()
    crawl_enabled: bool = True
    max_crawl_pages: int = 10
    max_crawl_depth: int = 1
    max_discovered_urls: int = 100
    automation_timezone: str = "UTC"
    blocked_bulk_hours: tuple[int, int] | None = None

    def bulk_automation_blocked(self, at: datetime | None = None) -> bool:
        if self.blocked_bulk_hours is None:
            return False
        moment = at or datetime.now(timezone.utc)
        local_hour = moment.astimezone(ZoneInfo(self.automation_timezone)).hour
        start, end = self.blocked_bulk_hours
        if start < end:
            return start <= local_hour < end
        return local_hour >= start or local_hour < end

    def seconds_until_bulk_allowed(self, at: datetime | None = None) -> int:
        """Seconds to sleep until bulk automation is permitted (0 if already allowed)."""
        if self.blocked_bulk_hours is None or not self.bulk_automation_blocked(at):
            return 0
        moment = at or datetime.now(timezone.utc)
        local = moment.astimezone(ZoneInfo(self.automation_timezone))
        _start, end = self.blocked_bulk_hours
        if end >= 24:
            open_local = (local + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            open_local = local.replace(hour=end, minute=0, second=0, microsecond=0)
            if open_local <= local:
                open_local += timedelta(days=1)
        return max(0, int((open_local - local).total_seconds()))

    @classmethod
    def load(cls, path: Path) -> "ScanConfig":
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        scope = data.get("scope", {})
        scan = data.get("scan", {})
        allow = tuple(scope.get("allow_hosts", ()))
        if not allow:
            raise ValueError("scope.allow_hosts must contain at least one authorized hostname")
        rps = float(scan.get("requests_per_second", 2.0))
        concurrency = int(scan.get("concurrency", 4))
        if not 0.1 <= rps <= 10:
            raise ValueError("requests_per_second must be between 0.1 and 10")
        if not 1 <= concurrency <= 10:
            raise ValueError("concurrency must be between 1 and 10")
        max_crawl_pages = int(scan.get("max_crawl_pages", 10))
        max_crawl_depth = int(scan.get("max_crawl_depth", 1))
        max_discovered_urls = int(scan.get("max_discovered_urls", 100))
        automation_timezone = str(scan.get("automation_timezone", "UTC"))
        try:
            ZoneInfo(automation_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown automation_timezone: {automation_timezone}") from exc
        raw_blocked_hours = scan.get("blocked_bulk_hours")
        blocked_bulk_hours: tuple[int, int] | None = None
        if raw_blocked_hours is not None:
            if not isinstance(raw_blocked_hours, list) or len(raw_blocked_hours) != 2:
                raise ValueError("blocked_bulk_hours must be [start_hour, end_hour]")
            start, end = (int(raw_blocked_hours[0]), int(raw_blocked_hours[1]))
            if not (0 <= start <= 23 and 1 <= end <= 24 and start != end):
                raise ValueError("blocked_bulk_hours must contain distinct hours in the 0..24 range")
            blocked_bulk_hours = (start, end)
        if not 1 <= max_crawl_pages <= 50:
            raise ValueError("max_crawl_pages must be between 1 and 50")
        if not 0 <= max_crawl_depth <= 2:
            raise ValueError("max_crawl_depth must be between 0 and 2")
        if not 1 <= max_discovered_urls <= 500:
            raise ValueError("max_discovered_urls must be between 1 and 500")
        return cls(
            scope=ScopePolicy(allow, tuple(scope.get("deny_hosts", ())), bool(scope.get("allow_http", False))),
            automation_allowed=bool(scan.get("automation_allowed", True)),
            requests_per_second=rps,
            concurrency=concurrency,
            timeout_seconds=min(max(float(scan.get("timeout_seconds", 10)), 1), 30),
            max_body_bytes=min(max(int(scan.get("max_body_bytes", 65_536)), 1024), 262_144),
            user_agent=str(scan.get("user_agent", DEFAULT_USER_AGENT)),
            excluded_finding_ids=tuple(str(item) for item in scan.get("excluded_finding_ids", ())),
            crawl_enabled=bool(scan.get("crawl_enabled", True)),
            max_crawl_pages=max_crawl_pages,
            max_crawl_depth=max_crawl_depth,
            max_discovered_urls=max_discovered_urls,
            automation_timezone=automation_timezone,
            blocked_bulk_hours=blocked_bulk_hours,
        )

