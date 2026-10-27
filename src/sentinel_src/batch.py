from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from .config import ScanConfig


MAX_BATCH_TARGETS = 50


def load_targets(path: Path, config: ScanConfig) -> list[str]:
    """Load, de-duplicate and scope-check an explicit target manifest."""
    targets: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value in seen:
            continue
        try:
            config.scope.validate_url(value, resolve_dns=False)
        except ValueError as exc:
            raise ValueError(f"targets line {line_number}: {exc}") from exc
        seen.add(value)
        targets.append(value)
        if len(targets) > MAX_BATCH_TARGETS:
            raise ValueError(f"a batch may contain at most {MAX_BATCH_TARGETS} explicit targets")
    if not targets:
        raise ValueError("target manifest contains no scan targets")
    return targets


def result_filename(target: str) -> str:
    host = (urlsplit(target).hostname or "target").replace(":", "_")
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:10]
    return f"{host}-{digest}.json"

