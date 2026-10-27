from __future__ import annotations

import hashlib
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from .models import Finding

SKIP_SUFFIXES = {
    ".7z", ".avi", ".css", ".dmg", ".doc", ".docx", ".gif", ".gz", ".ico", ".jpg", ".jpeg",
    ".mov", ".mp3", ".mp4", ".pdf", ".png", ".rar", ".svg", ".tar", ".webp", ".woff", ".woff2", ".xls", ".xlsx", ".zip",
}
STATEFUL_PATH_WORDS = {"delete", "destroy", "logout", "remove", "signout", "unsubscribe"}
URL_LITERAL = re.compile(r'''(?P<quote>["'])(?P<url>(?:https?://|/)[^"'<>\s]{1,500})(?P=quote)''')


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        for name in ("href", "src", "action"):
            if values.get(name):
                self.links.add(values[name] or "")


def _canonical_candidate(base_url: str, value: str) -> str | None:
    value = value.strip().rstrip("\\")
    if not value:
        return None
    if value.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
        return None
    absolute = urljoin(base_url, value)
    parsed = urlsplit(absolute)
    base = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != base.hostname:
        return None
    if parsed.query:
        return None
    path_lower = parsed.path.lower()
    if any(word in path_lower.split("/") for word in STATEFUL_PATH_WORDS):
        return None
    if any(path_lower.endswith(suffix) for suffix in SKIP_SUFFIXES):
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def discover_urls(base_url: str, content_type: str, body: str) -> list[str]:
    values: set[str] = set()
    if "html" in content_type.lower():
        parser = LinkParser()
        parser.feed(body)
        values.update(parser.links)
    for match in URL_LITERAL.finditer(body):
        values.add(match.group("url"))
    results = {_canonical_candidate(base_url, value) for value in values}
    return sorted(value for value in results if value)


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("private-key-material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "疑似私钥材料"),
    ("cloud-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "疑似云访问密钥标识"),
    ("debug-stack-trace", re.compile(r"(?im)(?:Traceback \(most recent call last\)|\bat [\w.$]+\([^\n]+:\d+\)|\b[A-Za-z.]+Exception:)"), "疑似调试堆栈"),
)


def passive_findings(url: str, body: str) -> list[Finding]:
    findings: list[Finding] = []
    for finding_id, pattern, label in SECRET_PATTERNS:
        match = pattern.search(body)
        if not match:
            continue
        fingerprint = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()[:16]
        findings.append(Finding(
            id=finding_id, title=label, severity="medium", url=url,
            description="公开响应中出现疑似敏感或调试信息特征。工具不会验证凭据或扩大访问。",
            evidence={"match_type": finding_id, "sha256_prefix": fingerprint},
            remediation="人工确认内容真实性、暴露范围和实际影响后轮换秘密或关闭调试输出。",
            confidence="medium", submittable=False, suspicious=True,
            triage_reason="只有形态信号；必须人工确认真实性、权限和实际影响",
        ))
    private_ips: set[str] = set()
    pattern = r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])"
    for candidate in re.findall(pattern, body):
        try:
            if ipaddress.ip_address(candidate).is_private:
                private_ips.add(candidate)
        except ValueError:
            pass
    if private_ips:
        fingerprints = [hashlib.sha256(value.encode()).hexdigest()[:12] for value in sorted(private_ips)[:5]]
        findings.append(Finding(
            id="private-address-disclosure", title="响应中出现内网地址线索", severity="info", url=url,
            description="公开响应包含私有地址形态；工具仅记录脱敏指纹。",
            evidence={"count": len(private_ips), "sha256_prefixes": fingerprints},
            remediation="检查前端资源和错误信息，移除不必要的内部拓扑信息。",
            confidence="medium", submittable=False, suspicious=True,
            triage_reason="内网地址暴露通常不可单独提交，需要证明进一步安全影响",
        ))
    return findings
