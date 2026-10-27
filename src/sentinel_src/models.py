from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    url: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    confidence: str = "medium"
    submittable: bool = False
    suspicious: bool = False
    triage_reason: str = "需要人工验证实际安全影响"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    errors: list[str]
    discovered_urls: list[str] = field(default_factory=list)
    scanned_urls: list[str] = field(default_factory=list)
    tool_version: str = "0.1.0"

    @classmethod
    def start(cls, target: str) -> "ScanResult":
        now = datetime.now(timezone.utc).isoformat()
        return cls(target, now, now, [], [])

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        data["candidate_count"] = sum(1 for finding in self.findings if finding.submittable)
        data["suspicious_count"] = sum(1 for finding in self.findings if finding.suspicious or finding.submittable)
        data["noise_count"] = sum(
            1 for finding in self.findings if not finding.submittable and not finding.suspicious
        )
        return data

