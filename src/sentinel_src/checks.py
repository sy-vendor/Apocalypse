from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from .models import Finding


SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "启用 HSTS，并评估 includeSubDomains 与 preload。"),
    "content-security-policy": ("medium", "部署限制明确的 Content-Security-Policy。"),
    "x-content-type-options": ("low", "设置 X-Content-Type-Options: nosniff。"),
    "referrer-policy": ("low", "设置适合业务的 Referrer-Policy。"),
    "permissions-policy": ("info", "用 Permissions-Policy 关闭不需要的浏览器能力。"),
}


def header_findings(url: str, headers: dict[str, str]) -> list[Finding]:
    normalized = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []
    for name, (severity, remediation) in SECURITY_HEADERS.items():
        if name not in normalized:
            findings.append(Finding(
                id=f"missing-{name}", title=f"缺少安全响应头：{name}", severity=severity,
                url=url, description="该响应未包含建议的浏览器安全策略头。需结合页面用途人工判断风险。",
                evidence={"missing_header": name}, remediation=remediation, confidence="high",
                submittable=False, triage_reason="仅属于安全加固项，没有可验证的实际影响",
            ))
    acao = normalized.get("access-control-allow-origin")
    acac = normalized.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        findings.append(Finding(
            id="cors-wildcard-credentials", title="潜在危险的 CORS 配置", severity="high", url=url,
            description="响应同时声明通配来源和凭据。浏览器通常会阻止该组合，但可能反映服务端 CORS 配置错误，需人工复核动态 Origin 行为。",
            evidence={"access-control-allow-origin": acao, "access-control-allow-credentials": acac},
            remediation="使用精确来源白名单，避免对不可信来源允许凭据。", confidence="medium",
            submittable=False, suspicious=True,
            triage_reason="该响应头组合通常被浏览器阻止，需先证明跨域数据影响",
        ))
    return findings


def cookie_findings(url: str, set_cookie_values: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_https = urlsplit(url).scheme == "https"
    for raw in set_cookie_values:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            missing = []
            if is_https and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                findings.append(Finding(
                    id=f"cookie-flags-{name}", title=f"Cookie {name} 缺少安全属性", severity="low", url=url,
                    description="Cookie 缺少一个或多个建议属性；是否可利用取决于其用途和页面上下文。",
                    evidence={"cookie_name": name, "missing": missing},
                    remediation="为敏感 Cookie 设置 Secure、HttpOnly 和适当的 SameSite 值。", confidence="high",
                    submittable=False, triage_reason="Cookie 属性缺失本身不足以证明漏洞，需要结合敏感会话影响",
                ))
    return findings

