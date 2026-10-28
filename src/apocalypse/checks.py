from __future__ import annotations

import hashlib
import re
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

import httpx

from .crawler import FormInfo
from .models import Finding


SECURITY_HEADERS = {
    "strict-transport-security": ("low", "Enable HSTS after validating all subdomains support HTTPS."),
    "content-security-policy": ("low", "Deploy a restrictive Content-Security-Policy."),
    "x-content-type-options": ("info", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("info", "Set an appropriate Referrer-Policy."),
    "permissions-policy": ("info", "Disable unnecessary browser features with Permissions-Policy."),
}

SECRET_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("secret.private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Exposed private key material"),
    ("secret.aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "Cloud access-key identifier in response"),
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT-like credential in response"),
)
STACK_TRACE = re.compile(
    r"(?im)(?:Traceback \(most recent call last\)|\bat [\w.$]+\([^\n]+:\d+\)|\b[A-Za-z.]+Exception:|Fatal error:.* on line \d+)"
)


def _finding(rule: str, title: str, severity: str, url: str, description: str, **kwargs: object) -> Finding:
    return Finding(rule, title, severity, str(kwargs.pop("confidence", "high")), url, description, **kwargs)


def analyze_headers(url: str, response: httpx.Response) -> list[Finding]:
    headers = {key.lower(): value for key, value in response.headers.items()}
    findings: list[Finding] = []
    for name, (severity, remediation) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(_finding(
                f"header.missing.{name}", f"Missing security header: {name}", severity, url,
                "The response does not include this browser hardening header.",
                evidence={"missing_header": name}, remediation=remediation, category="hardening",
            ))
    server = headers.get("server", "")
    if re.search(r"\d", server):
        findings.append(_finding(
            "banner.server-version", "Server version disclosed", "info", url,
            "The Server response header appears to expose version information.",
            evidence={"server": server[:120]}, remediation="Remove unnecessary version details from server banners.",
            category="information-disclosure",
        ))
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        findings.append(_finding(
            "cors.wildcard", "Permissive CORS origin", "low", url,
            "The response allows any origin. Risk depends on whether sensitive unauthenticated data is returned.",
            evidence={"access_control_allow_origin": "*", "credentials": acac},
            remediation="Restrict CORS to explicitly trusted origins.", category="cors", confidence="medium",
        ))
    return findings


def analyze_cookies(url: str, response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    secure_transport = urlsplit(url).scheme == "https"
    for raw in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except Exception:
            continue
        for name, morsel in parsed.items():
            missing: list[str] = []
            if secure_transport and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                findings.append(_finding(
                    "cookie.missing-flags", f"Cookie {name} is missing security attributes", "low", url,
                    "A cookie was issued without one or more recommended attributes.",
                    evidence={"cookie_name": name, "missing": missing},
                    remediation="Set Secure, HttpOnly, and an appropriate SameSite value for sensitive cookies.",
                    category="session",
                ))
    return findings


def analyze_body(url: str, text: str, forms: list[FormInfo], mixed: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rule, pattern, title in SECRET_RULES:
        match = pattern.search(text)
        if match:
            fingerprint = hashlib.sha256(match.group(0).encode()).hexdigest()[:16]
            findings.append(_finding(
                rule, title, "high", url,
                "The response contains a credential-like value. Apocalypse stores only a fingerprint.",
                evidence={"sha256_prefix": fingerprint}, remediation="Remove and rotate the exposed credential.",
                category="secret-exposure", confidence="medium",
            ))
    if STACK_TRACE.search(text):
        findings.append(_finding(
            "error.stack-trace", "Application stack trace disclosed", "medium", url,
            "The response contains a framework or runtime stack trace.", evidence={"pattern": "stack-trace"},
            remediation="Disable verbose error output in production.", category="information-disclosure",
        ))
    if re.search(r"(?i)<title>\s*index of /", text) or re.search(r"(?i)<h1>\s*index of /", text):
        findings.append(_finding(
            "directory.listing", "Directory listing enabled", "medium", url,
            "The server appears to expose an automatic directory index.", evidence={"indicator": "index of"},
            remediation="Disable directory indexing and restrict access to stored files.", category="misconfiguration",
        ))
    for resource in mixed[:10]:
        findings.append(_finding(
            "transport.mixed-content", "HTTPS page loads an HTTP resource", "low", url,
            "An HTTPS document references an insecure HTTP resource.", evidence={"resource": resource[:300]},
            remediation="Load all active and passive resources over HTTPS.", category="transport",
        ))
    for form in forms:
        password_inputs = [item for item in form.inputs if item.get("type") == "password"]
        if password_inputs and urlsplit(form.action).scheme == "http":
            findings.append(_finding(
                "form.password-over-http", "Password form submits over HTTP", "high", url,
                "A form containing a password field submits to an unencrypted URL.",
                evidence={"action": form.action, "method": form.method},
                remediation="Submit credentials only over HTTPS.", category="transport",
            ))
        if form.method == "POST":
            names = {item.get("name", "").lower() for item in form.inputs}
            if not any("csrf" in name or "token" in name for name in names):
                findings.append(_finding(
                    "form.csrf-token-heuristic", "POST form has no visible anti-CSRF token", "info", url,
                    "No obvious anti-CSRF field was found. The application may use another protection mechanism.",
                    evidence={"action": form.action, "input_count": len(form.inputs)},
                    remediation="Verify state-changing requests use robust CSRF defenses.", category="csrf", confidence="low",
                ))
    return findings


def deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    for item in findings:
        key = (item.rule_id, item.url, repr(sorted(item.evidence.items())))
        unique[key] = item
    return list(unique.values())

