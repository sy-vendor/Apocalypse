from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .models import Finding


def finding_fingerprint(item: Finding | dict[str, Any]) -> str:
    if isinstance(item, Finding):
        rule_id, url, evidence = item.rule_id, item.url, item.evidence
    else:
        rule_id = str(item.get("rule_id", ""))
        url = str(item.get("url", ""))
        evidence = item.get("evidence") or {}
    parsed = urlsplit(url)
    parameter = str(evidence.get("parameter", "")) if isinstance(evidence, dict) else ""
    method = str(evidence.get("method", "")) if isinstance(evidence, dict) else ""
    path = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return f"{rule_id}|{path}|{method}|{parameter}"


@dataclass(slots=True)
class BaselineComparison:
    baseline_scan_id: str | None = None
    new: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    recurring: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "recurring": len(self.recurring),
        }

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["summary"] = self.summary
        return data


def compare_findings(
    current: list[Finding] | list[dict[str, Any]],
    previous: list[Finding] | list[dict[str, Any]],
    *,
    baseline_scan_id: str | None,
) -> BaselineComparison:
    current_map = {finding_fingerprint(item): item for item in current}
    previous_map = {finding_fingerprint(item): item for item in previous}
    current_keys = set(current_map)
    previous_keys = set(previous_map)
    return BaselineComparison(
        baseline_scan_id=baseline_scan_id,
        new=sorted(current_keys - previous_keys),
        fixed=sorted(previous_keys - current_keys),
        recurring=sorted(current_keys & previous_keys),
    )
