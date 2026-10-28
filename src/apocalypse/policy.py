"""Scan policy: disable rules and exclude paths/parameters to control CI noise."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import Finding


@dataclass(slots=True)
class ScanPolicy:
    disabled_rules: set[str] = field(default_factory=set)
    exclude_paths: list[str] = field(default_factory=list)
    exclude_params: set[str] = field(default_factory=set)

    def allows_rule(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rules

    def allows_path(self, url: str) -> bool:
        path = urlsplit(url).path or "/"
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.rstrip("/"), pattern.rstrip("/")):
                return False
        return True

    def allows_param(self, name: str) -> bool:
        return name.lower() not in {item.lower() for item in self.exclude_params}

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        kept: list[Finding] = []
        for item in findings:
            if not self.allows_rule(item.rule_id):
                continue
            if not self.allows_path(item.url):
                continue
            param = str((item.evidence or {}).get("parameter") or "")
            if param and not self.allows_param(param):
                continue
            kept.append(item)
        return kept


def parse_policy_document(document: dict[str, Any]) -> ScanPolicy:
    if not isinstance(document, dict):
        raise ValueError("policy must be a JSON object")
    disabled = document.get("disabled_rules") or []
    paths = document.get("exclude_paths") or []
    params = document.get("exclude_params") or []
    if not isinstance(disabled, list) or not isinstance(paths, list) or not isinstance(params, list):
        raise ValueError("disabled_rules, exclude_paths, and exclude_params must be arrays")
    if len(disabled) > 200 or len(paths) > 200 or len(params) > 200:
        raise ValueError("policy lists are limited to 200 entries each")
    return ScanPolicy(
        disabled_rules={str(item).strip() for item in disabled if str(item).strip()},
        exclude_paths=[str(item).strip() for item in paths if str(item).strip()],
        exclude_params={str(item).strip() for item in params if str(item).strip()},
    )


def load_policy(path: Path) -> ScanPolicy:
    return parse_policy_document(json.loads(path.read_text(encoding="utf-8")))


def example_policy() -> dict[str, Any]:
    return {
        "disabled_rules": ["banner.server-version", "form.csrf-token-heuristic"],
        "exclude_paths": ["/health", "/ready", "/static/*", "/assets/*"],
        "exclude_params": ["utm_source", "utm_medium", "fbclid"],
    }
