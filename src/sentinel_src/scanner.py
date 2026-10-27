from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin

import httpx

from .checks import cookie_findings, header_findings
from .config import ScanConfig
from .discovery import discover_urls, passive_findings
from .models import Finding, ScanResult
from .scope import ScopeError

REDACTIONS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)([^\s,;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*[\"']?)([^\s\"',;]+)"), r"\1[REDACTED]"),
]


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def _pace(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            delay = (1 / self.config.requests_per_second) - (loop.time() - self._last_request)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request = loop.time()

    async def _get(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        self.config.scope.validate_url(url)
        current = url
        for _ in range(6):
            await self._pace()
            response = await client.get(current, follow_redirects=False)
            if not response.is_redirect:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = urljoin(str(response.url), location)
            self.config.scope.validate_url(current)
        raise ScopeError("Too many redirects")

    async def scan(self, target: str) -> ScanResult:
        self.config.scope.validate_url(target)
        result = ScanResult.start(target)
        limits = httpx.Limits(max_connections=self.config.concurrency)
        timeout = httpx.Timeout(self.config.timeout_seconds)
        headers = {"User-Agent": self.config.user_agent, "Accept": "text/html,application/json;q=0.8,*/*;q=0.1"}
        async with httpx.AsyncClient(timeout=timeout, limits=limits, headers=headers, verify=True) as client:
            queue: deque[tuple[str, int]] = deque([(target, 0)])
            queued = {target}
            while queue and len(result.scanned_urls) < self.config.max_crawl_pages:
                current, depth = queue.popleft()
                try:
                    response = await self._get(client, current)
                    final_url = str(response.url)
                    if final_url not in result.scanned_urls:
                        result.scanned_urls.append(final_url)
                    result.findings.extend(header_findings(final_url, dict(response.headers)))
                    result.findings.extend(cookie_findings(final_url, response.headers.get_list("set-cookie")))
                    content_type = response.headers.get("content-type", "")
                    body = response.content[: self.config.max_body_bytes].decode(
                        response.encoding or "utf-8", errors="replace"
                    )
                    if any(kind in content_type.lower() for kind in ("html", "javascript", "json", "text")):
                        result.findings.extend(passive_findings(final_url, body))
                        if self.config.crawl_enabled and depth < self.config.max_crawl_depth:
                            for discovered in discover_urls(final_url, content_type, body):
                                if len(result.discovered_urls) >= self.config.max_discovered_urls:
                                    break
                                if discovered not in queued:
                                    queued.add(discovered)
                                    result.discovered_urls.append(discovered)
                                    queue.append((discovered, depth + 1))
                    if response.status_code >= 500:
                        result.findings.append(Finding(
                            id="server-error", title="目标返回服务器错误", severity="info", url=final_url,
                            description="基线请求返回 5xx；这本身不是漏洞，建议由资产方检查服务状态。",
                            evidence={"status_code": response.status_code, "body_excerpt": redact(body[:512])},
                            remediation="检查服务端日志与异常处理。", confidence="high",
                            submittable=False, triage_reason="服务端错误本身不能证明安全影响",
                        ))
                except (httpx.HTTPError, ScopeError) as exc:
                    result.errors.append(f"{current}: {type(exc).__name__}: {exc}")

            for path in ("/.well-known/security.txt", "/robots.txt"):
                url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                try:
                    response = await self._get(client, url)
                    if path.endswith("security.txt") and response.status_code == 404:
                        result.findings.append(Finding(
                            id="missing-security-txt", title="未发现 security.txt", severity="info", url=url,
                            description="站点未在标准位置发布安全联系信息。", evidence={"status_code": 404},
                            remediation="按 RFC 9116 发布 security.txt。", confidence="high",
                            submittable=False, triage_reason="缺少安全联系文件不是可提交漏洞",
                        ))
                except (httpx.HTTPError, ScopeError) as exc:
                    result.errors.append(f"{path}: {type(exc).__name__}: {exc}")
        result.finish()
        if self.config.excluded_finding_ids:
            excluded = set(self.config.excluded_finding_ids)
            result.findings = [finding for finding in result.findings if finding.id not in excluded]
        unique: dict[tuple[str, str], Finding] = {}
        for finding in result.findings:
            unique[(finding.id, finding.url)] = finding
        result.findings = list(unique.values())
        return result

