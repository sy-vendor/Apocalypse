from __future__ import annotations

import asyncio
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import ScanConfig
from .models import Finding
from .scope import ScopeError

SUCCESS_STATUSES = {200, 201, 202, 203, 204, 206}
DENY_STATUSES = {401, 403, 404}


@dataclass(frozen=True, slots=True)
class AccountAuth:
    name: str
    headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class AuthzCheck:
    name: str
    url_template: str
    id_a: str
    id_b: str
    method: str = "GET"


@dataclass(slots=True)
class ResponseFingerprint:
    status_code: int
    body_length: int
    top_level_keys: list[str]
    body_sha256_prefix: str
    content_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "body_length": self.body_length,
            "top_level_keys": self.top_level_keys,
            "body_sha256_prefix": self.body_sha256_prefix,
            "content_type": self.content_type,
        }


@dataclass(slots=True)
class AuthzRunResult:
    target: str
    started_at: str
    finished_at: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    tool_version: str = "0.1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "checks_run": self.checks_run,
            "tool_version": self.tool_version,
            "candidate_count": sum(1 for finding in self.findings if finding.submittable),
            "suspicious_count": sum(
                1 for finding in self.findings if finding.suspicious or finding.submittable
            ),
            "noise_count": sum(
                1 for finding in self.findings if not finding.submittable and not finding.suspicious
            ),
        }


def load_auth_file(path: Path) -> tuple[AccountAuth, AccountAuth]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return _account_from_section(data, "account_a"), _account_from_section(data, "account_b")


def _account_from_section(data: dict[str, Any], key: str) -> AccountAuth:
    section = data.get(key)
    if not isinstance(section, dict):
        raise ValueError(f"auth file missing [{key}]")
    headers: dict[str, str] = {}
    raw_headers = section.get("headers") or {}
    if isinstance(raw_headers, dict):
        headers.update({str(k): str(v) for k, v in raw_headers.items()})
    cookie = section.get("cookie")
    if cookie:
        headers["Cookie"] = str(cookie)
    authorization = section.get("authorization")
    if authorization:
        headers["Authorization"] = str(authorization)
    if not headers:
        raise ValueError(f"[{key}] must provide cookie, authorization, or headers")
    return AccountAuth(name=key, headers=headers)


def load_authz_checks(path: Path) -> list[AuthzCheck]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    rows = data.get("checks")
    if not isinstance(rows, list) or not rows:
        raise ValueError("checks file must contain a non-empty [[checks]] list")
    checks: list[AuthzCheck] = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"checks[{index}] must be a table")
        method = str(row.get("method", "GET")).upper()
        if method != "GET":
            raise ValueError(f"checks[{index}]: only GET is allowed for authz-compare")
        url = str(row.get("url") or "").strip()
        if "{id}" not in url:
            raise ValueError(f"checks[{index}]: url must contain {{id}} placeholder")
        name = str(row.get("name") or f"check-{index}").strip()
        id_a = str(row.get("id_a") or "").strip()
        id_b = str(row.get("id_b") or "").strip()
        if not id_a or not id_b:
            raise ValueError(f"checks[{index}]: id_a and id_b are required")
        if id_a == id_b:
            raise ValueError(f"checks[{index}]: id_a and id_b must differ (use each account's own resource)")
        checks.append(AuthzCheck(name=name, url_template=url, id_a=id_a, id_b=id_b, method=method))
    return checks


def render_check_url(template: str, resource_id: str) -> str:
    return template.replace("{id}", resource_id)


def fingerprint_body(status_code: int, content_type: str, body: str) -> ResponseFingerprint:
    top_keys: list[str] = []
    text = body.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                top_keys = sorted(str(key) for key in parsed.keys())
            elif isinstance(parsed, list):
                top_keys = ["<array>"]
        except json.JSONDecodeError:
            top_keys = []
    digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
    return ResponseFingerprint(
        status_code=status_code,
        body_length=len(body.encode("utf-8", errors="replace")),
        top_level_keys=top_keys,
        body_sha256_prefix=digest,
        content_type=content_type.split(";")[0].strip().lower(),
    )


def key_similarity(keys_a: list[str], keys_b: list[str]) -> float:
    set_a, set_b = set(keys_a), set(keys_b)
    if not set_a and not set_b:
        return 1.0 if keys_a == keys_b else 0.0
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def structures_similar(owner: ResponseFingerprint, cross: ResponseFingerprint) -> bool:
    if owner.top_level_keys or cross.top_level_keys:
        return key_similarity(owner.top_level_keys, cross.top_level_keys) >= 0.8
    if owner.body_length == 0 and cross.body_length == 0:
        return True
    if owner.body_length == 0 or cross.body_length == 0:
        return False
    ratio = min(owner.body_length, cross.body_length) / max(owner.body_length, cross.body_length)
    return ratio >= 0.85 and owner.body_sha256_prefix == cross.body_sha256_prefix


def is_success(fp: ResponseFingerprint) -> bool:
    return fp.status_code in SUCCESS_STATUSES


def is_denied(fp: ResponseFingerprint) -> bool:
    return fp.status_code in DENY_STATUSES


def judge_cross_access(
    *,
    check_name: str,
    resource_owner: str,
    url: str,
    owner_fp: ResponseFingerprint,
    cross_fp: ResponseFingerprint,
    anon_fp: ResponseFingerprint | None,
) -> Finding | None:
    """Return a finding when cross-account access looks like an authz issue."""
    if not is_success(owner_fp):
        return None
    if not is_success(cross_fp):
        return None
    if not structures_similar(owner_fp, cross_fp):
        return None
    if anon_fp is not None and is_success(anon_fp) and structures_similar(owner_fp, anon_fp):
        return None

    strong = anon_fp is not None and is_denied(anon_fp)
    return Finding(
        id=f"authz-cross-read-{check_name}-{resource_owner}",
        title=f"疑似越权读取：{check_name}（{resource_owner} 资源）",
        severity="high" if strong else "medium",
        url=url,
        description=(
            "账号 B/A 跨读对方资源时返回成功，且响应结构指纹与资源所有者基线高度接近。"
            "这只是自动化差分信号，必须人工确认是否真正泄露私有数据后再提交。"
        ),
        evidence={
            "check": check_name,
            "resource_owner": resource_owner,
            "owner": owner_fp.to_dict(),
            "cross_account": cross_fp.to_dict(),
            "anonymous": anon_fp.to_dict() if anon_fp else None,
            "structure_similar": True,
            "anonymous_denied": bool(anon_fp and is_denied(anon_fp)),
        },
        remediation="按对象级授权校验资源归属；拒绝非所有者读取，并避免仅依赖隐藏 URL。",
        confidence="high" if strong else "medium",
        submittable=strong,
        suspicious=True,
        triage_reason=(
            "跨账号成功读取且结构指纹接近，未登录对照失败，标记为可提交候选（仍须人工复现）"
            if strong
            else "跨账号成功读取且结构指纹接近；缺少或未确认未登录拒绝，仅标可疑"
        ),
    )


class AuthzComparer:
    def __init__(self, config: ScanConfig, account_a: AccountAuth, account_b: AccountAuth):
        self.config = config
        self.account_a = account_a
        self.account_b = account_b
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def _pace(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            delay = (1 / self.config.requests_per_second) - (loop.time() - self._last_request)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = loop.time()

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str] | None,
    ) -> ResponseFingerprint:
        self.config.scope.validate_url(url)
        await self._pace()
        request_headers = {"User-Agent": self.config.user_agent, "Accept": "application/json, text/plain, */*"}
        if headers:
            request_headers.update(headers)
        response = await client.get(url, headers=request_headers, follow_redirects=False)
        body = response.content[: self.config.max_body_bytes].decode(
            response.encoding or "utf-8", errors="replace"
        )
        return fingerprint_body(response.status_code, response.headers.get("content-type", ""), body)

    async def run(self, checks: list[AuthzCheck]) -> AuthzRunResult:
        started = datetime.now(timezone.utc).isoformat()
        hosts = sorted({urlparse(render_check_url(check.url_template, check.id_a)).hostname or "" for check in checks})
        target_label = ",".join(h for h in hosts if h) or "authz-compare"
        result = AuthzRunResult(target=target_label, started_at=started, finished_at=started)
        timeout = httpx.Timeout(self.config.timeout_seconds)
        limits = httpx.Limits(max_connections=self.config.concurrency)
        async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=True) as client:
            for check in checks:
                result.checks_run.append(check.name)
                try:
                    await self._run_one(client, check, result)
                except (httpx.HTTPError, ScopeError, ValueError) as exc:
                    result.errors.append(f"{check.name}: {type(exc).__name__}: {exc}")
        result.finished_at = datetime.now(timezone.utc).isoformat()
        if self.config.excluded_finding_ids:
            excluded = set(self.config.excluded_finding_ids)
            result.findings = [finding for finding in result.findings if finding.id not in excluded]
        return result

    async def _run_one(self, client: httpx.AsyncClient, check: AuthzCheck, result: AuthzRunResult) -> None:
        url_a = render_check_url(check.url_template, check.id_a)
        url_b = render_check_url(check.url_template, check.id_b)
        owner_a = await self._get(client, url_a, self.account_a.headers)
        cross_b_on_a = await self._get(client, url_a, self.account_b.headers)
        anon_a = await self._get(client, url_a, None)
        finding_a = judge_cross_access(
            check_name=check.name,
            resource_owner="account_a",
            url=url_a,
            owner_fp=owner_a,
            cross_fp=cross_b_on_a,
            anon_fp=anon_a,
        )
        if finding_a:
            result.findings.append(finding_a)

        owner_b = await self._get(client, url_b, self.account_b.headers)
        cross_a_on_b = await self._get(client, url_b, self.account_a.headers)
        anon_b = await self._get(client, url_b, None)
        finding_b = judge_cross_access(
            check_name=check.name,
            resource_owner="account_b",
            url=url_b,
            owner_fp=owner_b,
            cross_fp=cross_a_on_b,
            anon_fp=anon_b,
        )
        if finding_b:
            result.findings.append(finding_b)


_MANUAL_FIELD = re.compile(
    r"^-\s*(?P<label>标题|严重性|URL|可提交候选|分流原因|描述)\s*[:：]\s*(?P<value>.*)\s*$",
    re.MULTILINE,
)


def parse_manual_review(path: Path) -> dict[str, Any]:
    """Parse a filled manual review markdown into an inbox-ready result. No network I/O."""
    text = path.read_text(encoding="utf-8")
    fields = {match.group("label"): match.group("value").strip() for match in _MANUAL_FIELD.finditer(text)}
    title = fields.get("标题") or "人工记录的可疑问题"
    url = fields.get("URL") or ""
    severity = fields.get("严重性") or "medium"
    submittable = fields.get("可提交候选", "").lower() in {"是", "yes", "true", "1"}
    description = fields.get("描述") or "来自人工验证记录；未由工具自动确认。"
    triage = fields.get("分流原因") or "人工填写，待整理提交"
    finding = {
        "id": f"manual-{hashlib.sha256((title + url).encode()).hexdigest()[:10]}",
        "title": title,
        "severity": severity,
        "url": url,
        "description": description,
        "evidence": {"source_file": str(path), "mode": "manual_review"},
        "remediation": "",
        "confidence": "medium",
        "submittable": submittable,
        "suspicious": True,
        "triage_reason": triage,
    }
    return {
        "target": url or str(path),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "findings": [finding],
        "errors": [],
        "source": str(path),
        "mode": "manual",
    }
