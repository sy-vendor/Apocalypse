from __future__ import annotations

import asyncio
import html
import json
import re
import secrets
from collections import deque
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from pathlib import Path

from .baseline import compare_findings
from .authz import score_idor, select_authz_candidates
from .browser import BrowserUnavailable, discover_with_browser, verify_reflected_xss
from .checks import analyze_body, analyze_cookies, analyze_headers, deduplicate
from .context import CONTEXT_SEVERITY, classify_reflection
from .crawler import FormInfo, parse_document
from .policy import ScanPolicy, parse_policy_document
from .graphql import (
    GraphQLError, INTROSPECTION_QUERY, candidate_graphql_urls, graphql_arg_probe_points, parse_introspection,
)
from .inject import (
    TIME_CONFIRM_THRESHOLD,
    boolean_chain_payloads,
    command_probe_payloads,
    detect_command_error,
    detect_sql_error,
    fingerprint_response,
    looks_injection_parameter,
    score_boolean_chain,
    score_time_chain,
    sql_probe_payloads,
    time_control_payload,
    time_payloads,
)
from .login import load_login_flow, parse_login_flow_document, replay_login_flow
from .models import Finding, ScanOptions, ScanResult, now_iso
from .oast import OastHub, validate_oast_base
from .openapi import OpenAPIError, discover_openapi_operations, discover_openapi_urls
from .probes import (
    detect_lfi, looks_path_parameter, looks_template_parameter, looks_url_parameter,
    lfi_canaries, score_ssti, ssrf_canaries, ssti_canaries,
)
from .scope import ScopeError, ScopePolicy
from .storage import Storage
from .webhook import deliver_webhook, scan_webhook_payload, validate_webhook_url


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    max_pages: int
    max_depth: int
    max_requests: int
    requests_per_second: float
    active_probes: bool
    max_probe_points: int


PROFILES = {
    "safe": ScanProfile("safe", 10, 1, 30, 0.5, False, 0),
    "balanced": ScanProfile("balanced", 30, 2, 140, 1.0, True, 20),
    "deep": ScanProfile("deep", 90, 3, 320, 1.5, True, 55),
}


FORBIDDEN_CUSTOM_HEADERS = {"connection", "content-length", "host", "proxy-authorization", "transfer-encoding"}
SENSITIVE_PARAMETER = re.compile(r"(?i)(?:pass|password|passwd|secret|token|csrf|otp|card|cvv|auth)")
UNSAFE_FORM_PATH = re.compile(r"(?i)(?:delete|destroy|logout|remove|signout|unsubscribe)")
LOGIN_PATH = re.compile(r"(?i)(?:^|/)(?:login|signin|sign-in|auth/login)(?:/|$)")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_ON_LEVELS = {"none", "medium", "high", "critical"}


def highest_finding_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda item: SEVERITY_RANK.get(item.severity, -1)).severity


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_RANK.get(fail_on)
    if threshold is None:
        raise ValueError(f"unknown fail-on level: {fail_on}")
    return any(SEVERITY_RANK.get(item.severity, -1) >= threshold for item in findings)


def validate_custom_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Validate caller-supplied authentication/context headers without logging their values."""
    if not headers:
        return {}
    if len(headers) > 20:
        raise ValueError("at most 20 custom headers are allowed")
    validated: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name, value = str(raw_name).strip(), str(raw_value).strip()
        if not name or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("custom header contains an invalid name")
        if name.lower() in FORBIDDEN_CUSTOM_HEADERS:
            raise ValueError(f"custom header is not allowed: {name}")
        if "\r" in value or "\n" in value or len(value) > 4096:
            raise ValueError(f"custom header has an invalid value: {name}")
        validated[name] = value
    return validated


def parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("custom headers must use 'Name: value' format")
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return validate_custom_headers(headers)


@dataclass(frozen=True, slots=True)
class ProbePoint:
    method: str
    url: str
    parameter: str
    values: tuple[tuple[str, str], ...]
    source: str
    location: str = "query"  # query | form | json | header | graphql
    graphql_query: str | None = None


@dataclass(frozen=True, slots=True)
class MaterializedProbe:
    url: str
    method: str
    data: list[tuple[str, str]] | None = None
    json_body: dict | list | None = None
    headers: dict[str, str] | None = None


def collect_probe_points(urls: list[str], forms: list[FormInfo], *, include_post: bool) -> list[ProbePoint]:
    """Build a deterministic, deduplicated inventory of non-sensitive input points."""
    points: list[ProbePoint] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(
        method: str, url: str, pairs: list[tuple[str, str]], source: str, *,
        location: str = "query", graphql_query: str | None = None,
    ) -> None:
        for name, _ in pairs:
            key = (method, url, name, location)
            if not name or SENSITIVE_PARAMETER.search(name) or key in seen:
                continue
            seen.add(key)
            points.append(ProbePoint(
                method, url, name, tuple(pairs), source, location=location, graphql_query=graphql_query,
            ))

    for url in urls:
        parsed = urlsplit(url)
        add("GET", urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
            parse_qsl(parsed.query, keep_blank_values=True), "query", location="query")
    for form in forms:
        method = form.method if form.method in {"GET", "POST"} else "GET"
        if method == "POST" and not include_post:
            continue
        if method == "POST" and (form.enctype != "application/x-www-form-urlencoded" or UNSAFE_FORM_PATH.search(urlsplit(form.action).path)):
            continue
        pairs = [
            (item.get("name", ""), item.get("value", ""))
            for item in form.inputs
            if item.get("name") and item.get("type") not in {"button", "file", "image", "password", "reset", "submit"}
        ]
        add(method, form.action, pairs, "form", location="form" if method == "POST" else "query")
    return points


def collect_api_probe_points(
    openapi_ops: list[dict], graphql_points: list[dict], *, include_json_body: bool,
) -> list[ProbePoint]:
    points: list[ProbePoint] = []
    seen: set[tuple[str, str, str, str]] = set()

    def push(point: ProbePoint) -> None:
        key = (point.method, point.url, point.parameter, point.location)
        if point.parameter and not SENSITIVE_PARAMETER.search(point.parameter) and key not in seen:
            seen.add(key)
            points.append(point)

    for op in openapi_ops:
        method = str(op.get("method") or "GET").upper()
        url = str(op.get("url") or "")
        query = [(str(n), str(v)) for n, v in (op.get("query") or [])]
        for name, _ in query:
            push(ProbePoint(method if method == "GET" else "GET", url.split("?", 1)[0], name, tuple(query), "openapi", "query"))
        if include_json_body:
            fields = [(str(n), str(v)) for n, v in (op.get("json_fields") or [])]
            for name, _ in fields:
                push(ProbePoint("POST", url.split("?", 1)[0], name, tuple(fields), "openapi", "json"))
        for name, value in (op.get("headers") or []):
            push(ProbePoint(method, url, str(name), ((str(name), str(value)),), "openapi", "header"))
    for item in graphql_points:
        query = str(item.get("graphql_query") or "")
        if not query or "{{PARAM}}" not in query:
            continue
        push(ProbePoint(
            "POST", str(item.get("url") or ""), str(item.get("parameter") or ""),
            ((str(item.get("parameter")), "apocalypse"),), "graphql", "graphql", query,
        ))
    return points


def materialize_probe(point: ProbePoint, payload: str) -> MaterializedProbe:
    if point.location == "graphql" and point.graphql_query:
        query = point.graphql_query.replace("{{PARAM}}", payload.replace("\\", "\\\\").replace('"', '\\"'))
        return MaterializedProbe(point.url, "POST", json_body={"query": query}, headers={
            "Content-Type": "application/json", "Accept": "application/json",
        })
    if point.location == "header":
        return MaterializedProbe(point.url, point.method, headers={point.parameter: payload})
    if point.location == "json":
        body = {name: (payload if name == point.parameter else value) for name, value in point.values}
        return MaterializedProbe(point.url, "POST", json_body=body, headers={
            "Content-Type": "application/json", "Accept": "application/json",
        })
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, value in point.values:
        if name == point.parameter and not replaced:
            value, replaced = payload, True
        updated.append((name, value))
    if point.method == "GET" or point.location == "query":
        parsed = urlsplit(point.url)
        return MaterializedProbe(
            urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(updated), "")), "GET",
        )
    return MaterializedProbe(point.url, point.method, data=updated)


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.interval = 1 / requests_per_second
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        async with self.lock:
            loop = asyncio.get_running_loop()
            remaining = self.interval - (loop.time() - self.last)
            if remaining > 0:
                await asyncio.sleep(remaining)
            self.last = loop.time()


class ScanEngine:
    def __init__(self, storage: Storage, *, timeout: float = 12.0, max_body_bytes: int = 262_144):
        self.storage = storage
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes

    def queue(self, target: str, profile: str = "safe", *, tenant_id: str = "default") -> ScanResult:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile: {profile}")
        scan_id = secrets.token_hex(8)
        result = ScanResult(scan_id=scan_id, target=target, profile=profile)
        self.storage.create_scan(result, tenant_id=tenant_id)
        return result

    async def run(
        self, result: ScanResult, *, allow_private: bool = False, options: ScanOptions | None = None,
    ) -> ScanResult:
        options = options or ScanOptions()
        oast: OastHub | None = None
        webhook_url: str | None = None
        try:
            profile = PROFILES[result.profile]
            custom_headers = validate_custom_headers(options.custom_headers)
            webhook_url = validate_webhook_url(options.webhook_url)
            if options.fail_on not in FAIL_ON_LEVELS:
                raise ValueError("fail_on must be one of: none, medium, high, critical")
            if options.submit_forms and profile.name != "deep":
                raise ValueError("form submission requires the deep profile")
            if options.blind_inject and profile.name != "deep":
                raise ValueError("blind injection requires the deep profile")
            oast_base = validate_oast_base(options.oast_base_url)
            oast = OastHub(public_base=oast_base, listen=options.oast_listen)
            policy = parse_policy_document(options.policy) if options.policy else ScanPolicy()
            secondary_headers = validate_custom_headers(options.secondary_headers)
            login_flow_obj = None
            login_secrets = dict(options.login_secrets or {})
            if options.login_flow_id and not options.login_flow_path:
                saved = self.storage.get_login_flow(options.login_flow_id)
                if not saved:
                    raise ValueError(f"login flow not found: {options.login_flow_id}")
                login_flow_obj = parse_login_flow_document(
                    saved["flow"], secret_overrides=login_secrets,
                )
            elif options.login_flow_path:
                login_flow_obj = load_login_flow(
                    Path(options.login_flow_path), secret_overrides=login_secrets,
                )
            if login_flow_obj is not None:
                try:
                    login = await replay_login_flow(
                        login_flow_obj, target=result.target, navigation_timeout_ms=int(self.timeout * 1000),
                    )
                except (BrowserUnavailable, ValueError, OSError, json.JSONDecodeError) as exc:
                    result.errors.append(f"login: {type(exc).__name__}: {exc}")
                else:
                    if login.errors:
                        result.errors.extend(f"login: {message}" for message in login.errors)
                    if login.cookie_header:
                        custom_headers = validate_custom_headers({**custom_headers, "Cookie": login.cookie_header})
                    if not login.ok:
                        result.findings.append(Finding(
                            "auth.login-replay-failed", "Recorded login flow did not reach a success state", "medium", "high",
                            login.final_url or result.target,
                            "The provided login recording finished without matching the expected authenticated destination.",
                            {"final_url": login.final_url, "step_errors": len(login.errors)},
                            "Update the login recording or refresh credentials supplied via environment variables.",
                            "authentication",
                        ))
                    else:
                        result.findings.append(Finding(
                            "auth.login-replay-ok", "Recorded login flow completed", "info", "high",
                            login.final_url,
                            "Chromium replayed the recorded login steps and captured a same-origin session cookie jar.",
                            {
                                "final_url": login.final_url,
                                "cookie_names": len(login.cookie_header.split(";")) if login.cookie_header else 0,
                            },
                            "Keep login recordings and secrets out of source control; prefer environment placeholders.",
                            "authentication",
                        ))
            scope = ScopePolicy(
                result.target,
                allow_private=allow_private,
                exact_origin=bool(custom_headers) or bool(options.login_flow_path) or bool(options.login_flow_id),
            )
            scope.validate(result.target)
            limiter = RateLimiter(profile.requests_per_second)
            result.status, result.started_at = "running", now_iso()
            self.storage.update_scan(result)
            headers = {
                "User-Agent": "Apocalypse/0.10 (authorized security assessment)",
                "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.8,*/*;q=0.2",
                **custom_headers,
            }
            limits = httpx.Limits(max_connections=2, max_keepalive_connections=2)
            openapi_ops: list[dict] = []
            graphql_probe_points: list[dict] = []
            async with httpx.AsyncClient(headers=headers, timeout=self.timeout, limits=limits, verify=True) as client:
                http_discovered: set[str] = {scope.target}
                browser_discovered: set[str] = set()
                seed_urls: list[str] = []
                if options.openapi_url:
                    seed_urls, openapi_ops = await self._load_openapi(
                        client, scope, limiter, profile, result, options.openapi_url,
                    )
                    http_discovered.update(seed_urls)
                browser_forms: list[FormInfo] = []
                if options.browser_crawl and result.stats.requests < profile.max_requests:
                    browser_urls, browser_forms = await self._browser_discovery(
                        scope, profile, result, custom_headers,
                    )
                    browser_discovered.update(browser_urls)
                    seed_urls.extend(browser_urls)
                if (options.graphql or options.graphql_url) and result.stats.requests < profile.max_requests:
                    graphql_urls, graphql_probe_points = await self._graphql_discovery(
                        client, scope, limiter, profile, result,
                        explicit_url=options.graphql_url,
                        discovered=list(http_discovered | browser_discovered | set(seed_urls)),
                    )
                    seed_urls.extend(graphql_urls)
                    http_discovered.update(graphql_urls)
                forms = browser_forms + await self._crawl(
                    client, scope, limiter, profile, result,
                    authenticated=bool(custom_headers) or bool(options.login_flow_path) or bool(options.login_flow_id),
                    seed_urls=seed_urls, discovered_http=http_discovered,
                )
                result.stats.discovered_http = len(http_discovered)
                result.stats.discovered_browser = len(browser_discovered)
                result.stats.discovered = len(http_discovered | browser_discovered)
                if profile.active_probes and result.stats.requests < profile.max_requests:
                    await self._active_probes(
                        client, scope, limiter, profile, result, forms,
                        include_post=options.submit_forms,
                        blind_inject=options.blind_inject,
                        api_probe=options.api_probe,
                        openapi_ops=openapi_ops,
                        graphql_points=graphql_probe_points,
                        oast=oast,
                        policy=policy,
                        custom_headers=custom_headers,
                        browser_verify=options.browser_verify or options.browser_crawl,
                    )
                if secondary_headers and result.stats.requests < profile.max_requests:
                    await self._authz_probes(
                        client, scope, limiter, profile, result,
                        primary_headers=custom_headers,
                        secondary_headers=secondary_headers,
                        policy=policy,
                    )
            result.findings = policy.filter_findings(deduplicate(result.findings))
            result.stats.findings = len(result.findings)
            result.baseline = self._baseline_for(result)
            result.status = "completed"
        except Exception as exc:
            result.errors.append(f"fatal: {type(exc).__name__}: {exc}")
            result.status = "failed"
        finally:
            if oast is not None:
                oast.close()
        result.finished_at = now_iso()
        self.storage.replace_findings(result.scan_id, result.findings)
        self.storage.update_scan(result)
        if webhook_url:
            try:
                await deliver_webhook(webhook_url, scan_webhook_payload(result))
            except Exception as exc:
                result.errors.append(f"webhook: {type(exc).__name__}: {exc}")
                self.storage.update_scan(result)
        return result

    def _baseline_for(self, result: ScanResult) -> dict:
        previous = self.storage.previous_completed_scan(result.target, before_scan_id=result.scan_id)
        if not previous:
            return {}
        comparison = compare_findings(
            result.findings, previous.get("findings_list", []),
            baseline_scan_id=str(previous["id"]),
        )
        return comparison.to_dict()

    async def _browser_discovery(
        self, scope: ScopePolicy, profile: ScanProfile, result: ScanResult, custom_headers: dict[str, str],
    ) -> tuple[list[str], list[FormInfo]]:
        remaining = profile.max_requests - result.stats.requests
        request_budget = min(40, remaining, max(8, remaining // 3))
        page_budget = min(8, max(1, profile.max_pages // 2))
        action_budget = min(12, max(2, page_budget * 2))
        try:
            discovery = await discover_with_browser(
                result.target,
                custom_headers=custom_headers,
                max_pages=page_budget,
                max_requests=request_budget,
                max_actions=action_budget,
                navigation_timeout_ms=int(self.timeout * 1000),
            )
        except BrowserUnavailable as exc:
            result.errors.append(f"browser: {exc}")
            return [], []

        result.stats.requests += discovery.requests
        result.errors.extend(f"browser: {message}" for message in discovery.errors)
        forms: list[FormInfo] = []
        for document in discovery.documents:
            try:
                scope.validate(document.url, resolve_dns=False)
            except ScopeError:
                continue
            result.crawled_urls.append(document.url)
            result.stats.pages += 1
            _, document_forms, mixed = parse_document(document.url, "text/html", document.html)
            forms.extend(document_forms)
            result.findings.extend(analyze_body(document.url, document.html, document_forms, mixed))

        accepted: list[str] = []
        for url in discovery.urls:
            try:
                accepted.append(scope.validate(url, resolve_dns=False))
            except ScopeError:
                continue
        return accepted, forms

    async def _load_openapi(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, document_url: str,
    ) -> tuple[list[str], list[dict]]:
        try:
            response = await self._request(client, scope, limiter, result, profile, document_url)
            response.raise_for_status()
            document = json.loads(response.content[: self.max_body_bytes])
            candidates = discover_openapi_urls(document, str(response.url), result.target)
            operations = discover_openapi_operations(document, str(response.url), result.target)
        except (httpx.HTTPError, ScopeError, RuntimeError, json.JSONDecodeError, OpenAPIError) as exc:
            result.errors.append(f"openapi: {type(exc).__name__}: {exc}")
            return [], []

        accepted: list[str] = []
        skipped = 0
        for candidate in candidates[: profile.max_pages * 10]:
            try:
                accepted.append(scope.validate(candidate, resolve_dns=False))
            except ScopeError:
                skipped += 1
        scoped_ops: list[dict] = []
        for op in operations:
            try:
                scope.validate(str(op.get("url") or ""), resolve_dns=False)
            except ScopeError:
                skipped += 1
                continue
            scoped_ops.append(op)
        if skipped:
            result.errors.append(f"openapi: skipped {skipped} endpoint(s) outside the authorized scope")
        return accepted, scoped_ops

    async def _graphql_discovery(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, *, explicit_url: str | None, discovered: list[str],
    ) -> tuple[list[str], list[dict]]:
        candidates = [explicit_url] if explicit_url else candidate_graphql_urls(result.target, discovered)
        accepted: list[str] = []
        probe_points: list[dict] = []
        for candidate in candidates:
            if result.stats.requests >= profile.max_requests:
                break
            try:
                validated = scope.validate(candidate, resolve_dns=False)
                response = await self._request(
                    client, scope, limiter, result, profile, validated,
                    method="POST",
                    json_body={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
            except (httpx.HTTPError, ScopeError, RuntimeError, ValueError) as exc:
                result.errors.append(f"graphql: {type(exc).__name__}: {exc}")
                continue
            content_type = response.headers.get("content-type", "").lower()
            if response.status_code >= 400 or "json" not in content_type:
                continue
            try:
                payload = json.loads(response.content[: self.max_body_bytes])
                operations, summary = parse_introspection(payload)
                probe_points = graphql_arg_probe_points(payload, validated)
            except (json.JSONDecodeError, GraphQLError) as exc:
                result.errors.append(f"graphql {validated}: {type(exc).__name__}: {exc}")
                continue
            result.findings.append(Finding(
                "graphql.introspection-enabled", "GraphQL introspection is enabled", "medium", "high",
                validated,
                "The endpoint answered a full schema introspection query. This expands the discoverable API surface.",
                summary,
                "Disable introspection in production or restrict it to authenticated operators.",
                "graphql",
                verified=True,
            ))
            accepted.append(validated)
            for operation in operations[:20]:
                if result.stats.requests >= profile.max_requests:
                    break
                try:
                    sample = await self._request(
                        client, scope, limiter, result, profile, validated,
                        method="POST",
                        json_body={"query": operation},
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                    )
                    if sample.status_code < 500:
                        accepted.append(validated)
                except (httpx.HTTPError, ScopeError, RuntimeError):
                    continue
            break
        return list(dict.fromkeys(accepted)), probe_points

    async def _request(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        result: ScanResult, profile: ScanProfile, url: str, *, headers: dict[str, str] | None = None,
        method: str = "GET", data: list[tuple[str, str]] | None = None,
        json_body: dict | None = None,
    ) -> httpx.Response:
        if result.stats.requests >= profile.max_requests:
            raise RuntimeError("request budget exhausted")
        current = scope.validate(url)
        for _ in range(5):
            await limiter.wait()
            result.stats.requests += 1
            request_headers = dict(headers or {})
            content = None
            if json_body is not None:
                method = "POST"
                request_headers.setdefault("Content-Type", "application/json")
                content = json.dumps(json_body).encode()
            elif method == "POST" and data is not None:
                request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                content = urlencode(data).encode()
            response = await client.request(
                method, current, headers=request_headers or None, content=content, follow_redirects=False,
            )
            if not response.is_redirect or method != "GET" or json_body is not None:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = scope.validate(urljoin(str(response.url), location))
        raise ScopeError("redirect limit exceeded")

    async def _crawl(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, *, authenticated: bool, seed_urls: list[str] | None = None,
        discovered_http: set[str] | None = None,
    ) -> list[FormInfo]:
        seeds = [scope.target, *(seed_urls or [])]
        queue: deque[tuple[str, int]] = deque((url, 0) for url in dict.fromkeys(seeds))
        queued = set(seeds)
        http_urls = discovered_http if discovered_http is not None else set(seeds)
        discovered_forms: list[FormInfo] = []
        auth_ok_seen = False
        session_expiry_reported = False
        auth_failure_streak = 0
        while queue and result.stats.pages < profile.max_pages and result.stats.requests < profile.max_requests:
            url, depth = queue.popleft()
            try:
                response = await self._request(client, scope, limiter, result, profile, url)
            except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
                continue
            final_url = str(response.url)
            login_like = bool(LOGIN_PATH.search(urlsplit(final_url).path))
            auth_rejected = response.status_code in {401, 403} or login_like
            if authenticated:
                if result.stats.pages == 0:
                    if response.status_code in {401, 403}:
                        result.findings.append(Finding(
                            "auth.access-denied", "Authentication context was rejected", "info", "high",
                            final_url, "The initial authenticated request was denied, so protected coverage may be incomplete.",
                            {"status_code": response.status_code},
                            "Check the supplied Authorization, Cookie, or API authentication header.", "authentication",
                        ))
                    elif login_like:
                        result.findings.append(Finding(
                            "auth.login-redirect", "Authentication context reached a login page", "info", "medium",
                            final_url, "The initial request ended on a login route, so protected coverage may be incomplete.",
                            {"status_code": response.status_code},
                            "Refresh the supplied session cookie or authentication header.", "authentication",
                        ))
                if auth_rejected:
                    auth_failure_streak += 1
                    if auth_ok_seen and not session_expiry_reported and auth_failure_streak >= 1:
                        session_expiry_reported = True
                        result.findings.append(Finding(
                            "auth.session-expired", "Authenticated session appears to have expired", "medium", "high",
                            final_url,
                            "After successful authenticated responses, the crawler later hit login or access-denied behavior.",
                            {"status_code": response.status_code, "login_like": login_like,
                             "failure_streak": auth_failure_streak},
                            "Refresh the session and re-run coverage for protected routes.", "authentication",
                        ))
                else:
                    auth_ok_seen = True
                    auth_failure_streak = 0
            result.crawled_urls.append(final_url)
            result.stats.pages += 1
            result.findings.extend(analyze_headers(final_url, response))
            result.findings.extend(analyze_cookies(final_url, response))
            content_type = response.headers.get("content-type", "")
            if not any(kind in content_type.lower() for kind in ("html", "javascript", "json", "text", "xml")):
                continue
            text = response.content[: self.max_body_bytes].decode(response.encoding or "utf-8", errors="replace")
            links, forms, mixed = parse_document(final_url, content_type, text)
            discovered_forms.extend(forms)
            result.findings.extend(analyze_body(final_url, text, forms, mixed))
            if (
                authenticated and auth_ok_seen
                and any(item.get("type") == "password" for form in forms for item in form.inputs)
            ):
                result.findings.append(Finding(
                    "auth.login-form-observed", "Login form observed after authenticated coverage", "info", "medium",
                    final_url,
                    "A password form appeared after earlier authenticated responses succeeded. This may indicate session loss.",
                    {"form_count": len(forms)},
                    "Confirm the session still reaches protected content, or capture a fresh authenticated context.",
                    "authentication",
                ))
            if depth >= profile.max_depth:
                continue
            for discovered in links:
                if discovered not in queued and len(queued) < profile.max_pages * 10:
                    try:
                        validated = scope.validate(discovered, resolve_dns=False)
                    except ScopeError:
                        continue
                    http_urls.add(validated)
                    queued.add(validated)
                    queue.append((validated, depth + 1))
        return discovered_forms

    async def _send_probe(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, materialized: MaterializedProbe,
    ) -> httpx.Response:
        return await self._request(
            client, scope, limiter, result, profile, materialized.url,
            method=materialized.method, data=materialized.data,
            json_body=materialized.json_body if isinstance(materialized.json_body, dict) else None,
            headers=materialized.headers,
        )

    async def _authz_probes(
        self, _client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, *, primary_headers: dict[str, str],
        secondary_headers: dict[str, str], policy: ScanPolicy,
    ) -> None:
        candidates = [
            item for item in select_authz_candidates(result.crawled_urls, limit=min(12, profile.max_probe_points))
            if policy.allows_path(item.url)
        ]
        base_headers = {
            "User-Agent": "Apocalypse/0.10 (authorized security assessment)",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.8,*/*;q=0.2",
        }
        # Isolated clients so primary Cookie/Authorization never leak into the secondary session.
        # Reuse the caller's transport when present (tests / custom mounts).
        transport = getattr(_client, "_transport", None) or getattr(_client, "transport", None)
        client_kwargs: dict = {"timeout": self.timeout, "verify": True}
        if transport is not None:
            client_kwargs["transport"] = transport
        async with httpx.AsyncClient(
            headers={**base_headers, **primary_headers}, **client_kwargs,
        ) as primary_client, httpx.AsyncClient(
            headers={**base_headers, **secondary_headers}, **client_kwargs,
        ) as secondary_client:
            for candidate in candidates:
                if result.stats.requests + 1 >= profile.max_requests:
                    break
                try:
                    primary = await self._request(
                        primary_client, scope, limiter, result, profile, candidate.url,
                    )
                    primary_body = primary.content[: self.max_body_bytes].decode(
                        primary.encoding or "utf-8", errors="replace",
                    )
                    if result.stats.requests >= profile.max_requests:
                        break
                    secondary = await self._request(
                        secondary_client, scope, limiter, result, profile, candidate.url,
                    )
                    secondary_body = secondary.content[: self.max_body_bytes].decode(
                        secondary.encoding or "utf-8", errors="replace",
                    )
                except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                    result.errors.append(f"authz probe {candidate.url}: {type(exc).__name__}: {exc}")
                    continue
                score = score_idor(primary.status_code, primary_body, secondary.status_code, secondary_body)
                if not score["differential"]:
                    continue
                if not policy.allows_rule("authz.idor-differential"):
                    continue
                result.findings.append(Finding(
                    "authz.idor-differential", "Possible IDOR / BOLA across two sessions",
                    "high", "high" if score["chain_verified"] else "medium", candidate.url,
                    "The same object URL returned highly similar successful responses under two distinct authentication contexts.",
                    {"selector": candidate.reason, **score, "data_extraction_attempted": False},
                    "Enforce object-level authorization checks per session identity; never rely on obscurity of IDs.",
                    "authorization", verified=bool(score["chain_verified"]),
                ))

    async def _active_probes(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, forms: list[FormInfo], *, include_post: bool,
        blind_inject: bool = False, api_probe: bool = True,
        openapi_ops: list[dict] | None = None, graphql_points: list[dict] | None = None,
        oast: OastHub | None = None, policy: ScanPolicy | None = None,
        custom_headers: dict[str, str] | None = None, browser_verify: bool = False,
    ) -> None:
        policy = policy or ScanPolicy()
        # Harmless CORS reflection check: authenticated scans retain their context but never change state.
        marker_origin = "https://apocalypse.invalid"
        try:
            response = await self._request(
                client, scope, limiter, result, profile, result.target, headers={"Origin": marker_origin}
            )
            acao = response.headers.get("access-control-allow-origin", "")
            if acao == marker_origin:
                confirm_origin = "https://confirm.apocalypse.invalid"
                confirmed = False
                if result.stats.requests < profile.max_requests:
                    try:
                        confirmation = await self._request(
                            client, scope, limiter, result, profile, result.target,
                            headers={"Origin": confirm_origin},
                        )
                        confirmed = confirmation.headers.get("access-control-allow-origin", "") == confirm_origin
                    except (httpx.HTTPError, ScopeError, RuntimeError):
                        confirmed = False
                result.findings.append(Finding(
                    "cors.origin-reflection", "Arbitrary Origin reflected by CORS", "medium",
                    "high" if confirmed else "medium", str(response.url),
                    "The server reflected synthetic cross-origin Origin values. Repeated reflection raises confidence but risk still depends on sensitive content.",
                    {"origins_tested": 2 if confirmed else 1,
                     "credentials": response.headers.get("access-control-allow-credentials", "")},
                    "Use an explicit allowlist and verify sensitive responses cannot be read cross-origin.", "cors",
                    verified=confirmed,
                ))
        except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
            result.errors.append(f"cors probe: {type(exc).__name__}: {exc}")

        points = collect_probe_points(result.crawled_urls, forms, include_post=include_post)
        if api_probe:
            points.extend(collect_api_probe_points(
                openapi_ops or [], graphql_points or [], include_json_body=include_post or profile.name == "deep",
            ))
        points = [
            point for point in points
            if policy.allows_path(point.url) and policy.allows_param(point.parameter)
        ]
        # Prefer API / named-injection params early while request budget remains.
        points.sort(key=lambda p: (
            0 if p.source in {"openapi", "graphql"} else 1,
            0 if looks_injection_parameter(p.parameter) or looks_url_parameter(p.parameter)
            or looks_path_parameter(p.parameter) or looks_template_parameter(p.parameter) else 1,
        ))
        injection_budget = min(10, profile.max_probe_points)
        injection_used = 0
        special_budget = min(8, profile.max_probe_points)
        special_used = 0
        blind_budget = min(4, profile.max_probe_points) if blind_inject else 0
        blind_used = 0
        browser_verify_budget = 3 if browser_verify else 0
        browser_verify_used = 0
        for point in points[:profile.max_probe_points]:
            if result.stats.requests >= profile.max_requests:
                break
            marker = f"apocalypse_{result.scan_id[:8]}"
            redirect_names = {"next", "redirect", "redirect_uri", "return", "returnurl", "url", "continue"}
            redirect_probe = point.parameter.lower() in redirect_names and point.location in {"query", "form", "json"}
            payload = f"https://apocalypse.invalid/{marker}" if redirect_probe else f'{marker}\"><apocalypse>'
            try:
                response = await self._send_probe(
                    client, scope, limiter, profile, result, materialize_probe(point, payload),
                )
            except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                result.errors.append(f"parameter probe {point.method} {point.url}: {type(exc).__name__}: {exc}")
                continue
            body = response.content[: self.max_body_bytes].decode(response.encoding or "utf-8", errors="replace")
            content_type = response.headers.get("content-type", "").lower()
            if not redirect_probe and payload in body and ("html" in content_type or point.location == "graphql"):
                reflection = classify_reflection(body, marker)
                confirmed = False
                confirm_context: str | None = None
                if result.stats.requests < profile.max_requests:
                    confirm_payload = f"{marker}_confirm'><apocalypse-confirm>"
                    try:
                        confirmation = await self._send_probe(
                            client, scope, limiter, profile, result, materialize_probe(point, confirm_payload),
                        )
                        confirm_body = confirmation.content[: self.max_body_bytes].decode(
                            confirmation.encoding or "utf-8", errors="replace",
                        )
                        confirmed = confirm_payload in confirm_body
                        if confirmed:
                            confirm_context = classify_reflection(confirm_body, confirm_payload).kind
                    except (httpx.HTTPError, ScopeError, RuntimeError):
                        confirmed = False
                severity = reflection.severity
                if confirm_context:
                    confirm_severity = CONTEXT_SEVERITY.get(
                        confirm_context, (reflection.severity, reflection.confidence),
                    )[0]
                    if SEVERITY_RANK.get(confirm_severity, 0) > SEVERITY_RANK.get(severity, 0):
                        severity = confirm_severity
                execution_confirmed = False
                dialog_message = None
                dangerous = reflection.kind in {
                    "javascript", "event_handler", "attribute_unquoted", "attribute_double", "attribute_single",
                } or (confirm_context in {
                    "javascript", "event_handler", "attribute_unquoted", "attribute_double", "attribute_single",
                } if confirm_context else False)
                if (
                    browser_verify
                    and confirmed
                    and dangerous
                    and browser_verify_used < browser_verify_budget
                    and point.method == "GET"
                    and point.location == "query"
                    and policy.allows_rule("xss.reflected-unencoded")
                ):
                    xss_token = f"APOCALYPSE_XSS_{result.scan_id[:6]}"
                    exec_payload = f'"><img src=x onerror=alert("{xss_token}")>'
                    exec_url = materialize_probe(point, exec_payload).url
                    try:
                        verdict = await verify_reflected_xss(
                            exec_url, target=result.target, custom_headers=custom_headers or {},
                            marker=xss_token,
                        )
                        browser_verify_used += 1
                        execution_confirmed = verdict.executed
                        dialog_message = verdict.dialog_message
                        if verdict.error:
                            result.errors.append(f"xss browser verify: {verdict.error}")
                    except BrowserUnavailable as exc:
                        result.errors.append(f"xss browser verify: {exc}")
                if policy.allows_rule("xss.reflected-unencoded"):
                    result.findings.append(Finding(
                        "xss.reflected-unencoded", "Input repeatedly reflected into HTML without encoding",
                        "high" if execution_confirmed else severity,
                        "high" if execution_confirmed or confirmed else reflection.confidence, point.url,
                        "Distinct HTML metacharacter canaries were returned without encoding."
                        + (" Chromium executed a dialog canary." if execution_confirmed else " Context classified without assuming script execution."),
                        {"parameter": point.parameter, "method": point.method, "source": point.source,
                         "location": point.location, "status_code": response.status_code, "marker": marker,
                         "reflection_context": reflection.kind, "confirmation_context": confirm_context,
                         "confirmation_requests": 2 if confirmed else 1,
                         "execution_confirmed": execution_confirmed, "dialog_message": dialog_message},
                        "Apply context-aware output encoding and a restrictive Content-Security-Policy.", "xss",
                        verified=execution_confirmed or confirmed,
                    ))
            elif marker in body or html.escape(payload, quote=True) in body:
                if policy.allows_rule("input.reflection"):
                    reflection = classify_reflection(body, marker)
                    result.findings.append(Finding(
                        "input.reflection", "Input value reflected in response", "info", reflection.confidence, point.url,
                        "A harmless canary supplied to an input point was reflected. This alone is not proof of XSS.",
                        {"parameter": point.parameter, "method": point.method, "source": point.source,
                         "location": point.location, "status_code": response.status_code, "marker": marker,
                         "reflection_context": reflection.kind},
                        "Apply context-aware output encoding and validate untrusted input.", "input-validation",
                    ))
            if redirect_probe and policy.allows_rule("redirect.external"):
                location = response.headers.get("location", "")
                if urlsplit(location).hostname == "apocalypse.invalid":
                    result.findings.append(Finding(
                        "redirect.external", "External redirect accepted", "medium", "high", point.url,
                        "A navigation parameter accepted an external destination. The scanner did not follow it.",
                        {"parameter": point.parameter, "method": point.method, "location_host": "apocalypse.invalid"},
                        "Allow only relative paths or explicitly trusted destinations.", "redirect",
                    ))

            if special_used < special_budget and result.stats.requests < profile.max_requests:
                ran = await self._special_probes(
                    client, scope, limiter, profile, result, point, marker=marker, oast=oast,
                )
                if ran:
                    special_used += 1

            if (
                looks_injection_parameter(point.parameter)
                and injection_used < injection_budget
                and result.stats.requests < profile.max_requests
            ):
                injection_used += 1
                await self._injection_probes(
                    client, scope, limiter, profile, result, point, marker=marker,
                    blind_inject=blind_inject and blind_used < blind_budget,
                )
                if blind_inject and looks_injection_parameter(point.parameter):
                    blind_used += 1

    async def _special_probes(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, point: ProbePoint, *, marker: str,
        oast: OastHub | None,
    ) -> bool:
        """LFI / SSTI / SSRF(+OAST) confirmation chains. Returns True if any probe family ran."""
        ran = False

        async def once(payload: str) -> str:
            response = await self._send_probe(
                client, scope, limiter, profile, result, materialize_probe(point, payload),
            )
            return response.content[: self.max_body_bytes].decode(response.encoding or "utf-8", errors="replace")

        if looks_path_parameter(point.parameter) and result.stats.requests < profile.max_requests:
            ran = True
            for canary in lfi_canaries()[:2]:
                if result.stats.requests >= profile.max_requests:
                    break
                try:
                    body = await once(canary.primary)
                except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                    result.errors.append(f"lfi probe {point.url}: {type(exc).__name__}: {exc}")
                    break
                hit = detect_lfi(body)
                if not hit:
                    continue
                confirmed = False
                if result.stats.requests < profile.max_requests:
                    try:
                        confirm_body = await once(canary.confirm)
                        confirmed = detect_lfi(confirm_body) is not None
                    except (httpx.HTTPError, ScopeError, RuntimeError):
                        confirmed = False
                result.findings.append(Finding(
                    "lfi.path-traversal", "Possible local file inclusion / path traversal",
                    "high" if confirmed else "medium", "high" if confirmed else "medium", point.url,
                    "File-content fingerprints appeared after path-traversal canaries. No arbitrary file exfiltration beyond the canary was attempted.",
                    {"parameter": point.parameter, "method": point.method, "source": point.source,
                     "location": point.location, "fingerprint": hit, "canary": canary.kind,
                     "confirmation_requests": 2 if confirmed else 1},
                    "Normalize and allowlist filesystem paths; never concatenate untrusted input into file APIs.",
                    "lfi", verified=confirmed,
                ))
                break

        if looks_template_parameter(point.parameter) and result.stats.requests < profile.max_requests:
            ran = True
            for canary in ssti_canaries()[:2]:
                if result.stats.requests >= profile.max_requests:
                    break
                try:
                    primary_body = await once(canary.primary)
                    if result.stats.requests >= profile.max_requests:
                        break
                    confirm_body = await once(canary.confirm)
                except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                    result.errors.append(f"ssti probe {point.url}: {type(exc).__name__}: {exc}")
                    break
                score = score_ssti(primary_body, confirm_body, primary=canary.primary, confirm=canary.confirm)
                if score["saw_49"] or score["template_error_hint"]:
                    result.findings.append(Finding(
                        "ssti.template-injection", "Possible server-side template injection",
                        "high" if score["chain_verified"] else "medium",
                        "high" if score["chain_verified"] else "medium", point.url,
                        "Template arithmetic canaries produced evaluation-like output. No RCE payload was executed.",
                        {"parameter": point.parameter, "method": point.method, "source": point.source,
                         "location": point.location, "kind": canary.kind, **score},
                        "Do not render untrusted input as templates; sandbox or disable expression evaluation.",
                        "ssti", verified=bool(score["chain_verified"]),
                    ))
                    break

        if (
            oast and oast.enabled()
            and looks_url_parameter(point.parameter)
            and result.stats.requests < profile.max_requests
        ):
            ran = True
            token = oast.issue("ssrf")
            primary, confirm = ssrf_canaries(token.http_url, marker)
            try:
                await once(primary)
                if result.stats.requests < profile.max_requests:
                    await once(confirm)
            except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                result.errors.append(f"ssrf probe {point.url}: {type(exc).__name__}: {exc}")
                return ran
            await asyncio.sleep(0.35)
            hits = await oast.poll(token)
            if hits:
                result.findings.append(Finding(
                    "ssrf.oast-callback", "Server fetched an out-of-band collaborator URL",
                    "high", "high", point.url,
                    "An injected collaborator URL received an inbound interaction, indicating server-side request forgery behavior. No internal-network pivoting was attempted.",
                    {"parameter": point.parameter, "method": point.method, "source": point.source,
                     "location": point.location, "oast_token": token.id, "interactions": len(hits),
                     "oast_url_host": urlsplit(token.http_url).hostname},
                    "Validate and allowlist outbound URL destinations; block link-local/metadata ranges.",
                    "ssrf", verified=True,
                ))
        return ran

    async def _injection_probes(
        self, client: httpx.AsyncClient, scope: ScopePolicy, limiter: RateLimiter,
        profile: ScanProfile, result: ScanResult, point: ProbePoint, *, marker: str,
        blind_inject: bool = False,
    ) -> None:
        import time

        sql_primary, sql_confirm = sql_probe_payloads(marker)
        cmd_primary, cmd_confirm = command_probe_payloads(marker)

        async def once(payload: str) -> tuple[httpx.Response, str, float]:
            started = time.perf_counter()
            response = await self._send_probe(
                client, scope, limiter, profile, result, materialize_probe(point, payload),
            )
            elapsed = time.perf_counter() - started
            body = response.content[: self.max_body_bytes].decode(response.encoding or "utf-8", errors="replace")
            return response, body, elapsed

        try:
            _, body, _ = await once(sql_primary)
        except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
            result.errors.append(f"sqli probe {point.method} {point.url}: {type(exc).__name__}: {exc}")
            return
        sql_hit = detect_sql_error(body)
        if sql_hit and result.stats.requests < profile.max_requests:
            confirmed = False
            try:
                _, confirm_body, _ = await once(sql_confirm)
                confirmed = detect_sql_error(confirm_body) is not None
            except (httpx.HTTPError, ScopeError, RuntimeError):
                confirmed = False
            result.findings.append(Finding(
                "sqli.error-based", "Possible SQL error disclosure from crafted input", "high" if confirmed else "medium",
                "high" if confirmed else "medium", point.url,
                "Database error text appeared after a harmless quote canary. This is heuristic evidence, not proof of exploitable SQLi.",
                {"parameter": point.parameter, "method": point.method, "source": point.source,
                 "location": point.location, "error_fingerprint": sql_hit, "confirmation_requests": 2 if confirmed else 1,
                 "data_extraction_attempted": False},
                "Use parameterized queries and avoid returning raw database errors to clients.", "injection",
                verified=confirmed,
            ))

        if result.stats.requests >= profile.max_requests:
            return
        try:
            _, cmd_body, _ = await once(cmd_primary)
        except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
            result.errors.append(f"cmdi probe {point.method} {point.url}: {type(exc).__name__}: {exc}")
            return
        cmd_hit = detect_command_error(cmd_body)
        if cmd_hit and result.stats.requests < profile.max_requests:
            confirmed = False
            try:
                _, confirm_body, _ = await once(cmd_confirm)
                confirmed = detect_command_error(confirm_body) is not None
            except (httpx.HTTPError, ScopeError, RuntimeError):
                confirmed = False
            result.findings.append(Finding(
                "cmdi.error-based", "Possible OS command error disclosure from crafted input",
                "high" if confirmed else "medium", "high" if confirmed else "medium", point.url,
                "Shell/command error text appeared after a harmless metacharacter canary. No destructive command was executed.",
                {"parameter": point.parameter, "method": point.method, "source": point.source,
                 "location": point.location, "error_fingerprint": cmd_hit, "confirmation_requests": 2 if confirmed else 1,
                 "command_execution_attempted": False},
                "Avoid passing untrusted input to OS shells; use safe APIs and strict allowlists.", "injection",
                verified=confirmed,
            ))

        if not blind_inject or result.stats.requests >= profile.max_requests:
            return

        true_payload, false_payload, true_again_payload = boolean_chain_payloads(marker)
        try:
            true_response, true_body, _ = await once(true_payload)
            if result.stats.requests >= profile.max_requests:
                return
            false_response, false_body, _ = await once(false_payload)
            if result.stats.requests >= profile.max_requests:
                return
            true_again_response, true_again_body, _ = await once(true_again_payload)
        except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
            result.errors.append(f"blind boolean probe {point.method} {point.url}: {type(exc).__name__}: {exc}")
            return
        chain = score_boolean_chain(
            fingerprint_response(true_response.status_code, true_body),
            fingerprint_response(false_response.status_code, false_body),
            fingerprint_response(true_again_response.status_code, true_again_body),
        )
        if chain["differential"]:
            result.findings.append(Finding(
                "sqli.boolean-blind", "Possible boolean-based blind SQL injection", "high",
                "high" if chain["chain_verified"] else "medium", point.url,
                "A true/false/true exploit-chain check found differential responses without extracting database contents.",
                {"parameter": point.parameter, "method": point.method, "source": point.source,
                 "location": point.location, **chain, "data_extraction_attempted": False, "exploit_chain": "boolean-TFT"},
                "Use parameterized queries and normalize error/empty-result handling.", "injection",
                verified=bool(chain["chain_verified"]),
            ))

        if result.stats.requests >= profile.max_requests:
            return
        for payload in time_payloads()[:1]:
            try:
                _, _, control_elapsed = await once(time_control_payload())
                if result.stats.requests >= profile.max_requests:
                    return
                _, _, elapsed = await once(payload)
            except (httpx.HTTPError, ScopeError, RuntimeError) as exc:
                result.errors.append(f"blind time probe {point.method} {point.url}: {type(exc).__name__}: {exc}")
                return
            if elapsed < TIME_CONFIRM_THRESHOLD or result.stats.requests >= profile.max_requests:
                continue
            try:
                _, _, confirm_elapsed = await once(payload)
            except (httpx.HTTPError, ScopeError, RuntimeError):
                confirm_elapsed = 0.0
            time_chain = score_time_chain(control_elapsed, elapsed, confirm_elapsed)
            result.findings.append(Finding(
                "sqli.time-based", "Possible time-based blind SQL injection",
                "high" if time_chain["chain_verified"] else "medium",
                "high" if time_chain["chain_verified"] else "medium", point.url,
                "Control vs bounded-delay vs confirmation timings indicate a time-based injection chain. No stacked sleeps or data extraction.",
                {"parameter": point.parameter, "method": point.method, "source": point.source,
                 "location": point.location, **time_chain, "data_extraction_attempted": False,
                 "exploit_chain": "time-control-delay-confirm"},
                "Use parameterized queries and disable multi-statement execution where possible.", "injection",
                verified=bool(time_chain["chain_verified"]),
            ))
            break

