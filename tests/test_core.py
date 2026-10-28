from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl

import httpx

from apocalypse.baseline import compare_findings, finding_fingerprint
from apocalypse.checks import analyze_body, analyze_headers
from apocalypse.browser import BrowserDiscovery, RenderedDocument, cookies_from_header, normalize_browser_url, same_origin
from apocalypse.context import classify_reflection
from apocalypse.crawler import FormInfo, parse_document
from apocalypse.engine import (
    PROFILES, RateLimiter, ScanEngine, collect_probe_points, parse_header_lines, should_fail,
    validate_custom_headers,
)
from apocalypse.graphql import GraphQLError, parse_introspection
from apocalypse.campaign import CampaignSpec, create_campaign
from apocalypse.inject import (
    boolean_chain_payloads, boolean_payloads, detect_command_error, detect_sql_error,
    fingerprint_response, looks_injection_parameter, score_boolean_chain, score_time_chain,
)
from apocalypse.login import _redact_recorded_steps, load_login_flow, parse_login_flow_document
from apocalypse.models import Finding, ScanResult
from apocalypse.authz import score_idor, select_authz_candidates
from apocalypse.browser import XssBrowserVerdict
from apocalypse.oast import OastHit, OastHub
from apocalypse.openapi import OpenAPIError, discover_openapi_operations, discover_openapi_urls
from apocalypse.policy import parse_policy_document
from apocalypse.probes import detect_lfi, score_ssti
from apocalypse.reporting import lang_from_request, render_html, render_sarif
from apocalypse.schedule import create_schedule
from apocalypse.scope import ScopeError, ScopePolicy
from apocalypse.sso import tenant_slug, validate_oidc_config
from apocalypse.storage import Storage
from apocalypse.taxonomy import annotate_finding, taxonomy_for
from apocalypse.team import create_user_record, role_allows
from apocalypse.tickets import finding_ticket_key, validate_ticket_config
from apocalypse.webhook import scan_webhook_payload, validate_webhook_url


class ScopeTests(unittest.TestCase):
    def test_exact_host_only(self):
        policy = ScopePolicy("https://app.example.com/", allow_private=True)
        self.assertEqual(policy.validate("https://app.example.com/a", resolve_dns=False), "https://app.example.com/a")
        with self.assertRaises(ScopeError):
            policy.validate("https://cdn.example.com/a", resolve_dns=False)

    def test_credentials_rejected(self):
        with self.assertRaises(ScopeError):
            ScopePolicy("https://user:pass@example.com/")

    def test_custom_header_scope_can_be_pinned_to_origin(self):
        policy = ScopePolicy("https://app.example.com/", allow_private=True, exact_origin=True)
        self.assertEqual(policy.validate("https://app.example.com/a", resolve_dns=False), "https://app.example.com/a")
        with self.assertRaises(ScopeError):
            policy.validate("http://app.example.com/a", resolve_dns=False)
        with self.assertRaises(ScopeError):
            policy.validate("https://app.example.com:8443/a", resolve_dns=False)


class CrawlTests(unittest.TestCase):
    def test_document_parser_stays_same_host_and_skips_stateful_links(self):
        html = '''<a href="/account">A</a><a href="/logout">L</a><a href="https://outside.test/x">X</a>
        <script src="/app.js"></script><form method="post" action="/profile"><input name="email"></form>'''
        links, forms, mixed = parse_document("https://app.example.com/", "text/html", html)
        self.assertEqual(links, ["https://app.example.com/account", "https://app.example.com/app.js", "https://app.example.com/profile"])
        self.assertEqual(forms[0].method, "POST")
        self.assertEqual(forms[0].source_url, "https://app.example.com/")
        self.assertEqual(mixed, [])

    def test_form_values_and_extended_controls_are_captured(self):
        html = '''<form method="get" action="/search"><input name="q" value="hello">
        <textarea name="notes"></textarea><select name="kind"><option>all</option></select></form>'''
        _, forms, _ = parse_document("https://app.example.com/", "text/html", html)
        self.assertEqual([item["name"] for item in forms[0].inputs], ["q", "notes", "kind"])
        self.assertEqual(forms[0].inputs[0]["value"], "hello")


class BrowserTests(unittest.TestCase):
    def test_browser_urls_are_exact_origin_and_state_safe(self):
        target = "https://app.example.com/"
        self.assertTrue(same_origin("https://app.example.com:443/dashboard", target))
        self.assertFalse(same_origin("http://app.example.com/dashboard", target))
        self.assertFalse(same_origin("https://app.example.com:8443/dashboard", target))
        self.assertEqual(
            normalize_browser_url(target, "/dashboard#summary", target),
            "https://app.example.com/dashboard",
        )
        self.assertIsNone(normalize_browser_url(target, "/logout", target))
        self.assertIsNone(normalize_browser_url(target, "https://cdn.example.com/x", target))

    def test_cookie_header_becomes_scoped_browser_cookies(self):
        cookies = cookies_from_header("session=abc; theme=dark; $Path=/", "https://app.example.com/start")
        self.assertEqual([item["name"] for item in cookies], ["session", "theme"])
        self.assertTrue(all(item["url"] == "https://app.example.com/" for item in cookies))

    def test_engine_merges_browser_documents_and_request_counts(self):
        discovery = BrowserDiscovery(
            urls=["http://127.0.0.1/spa"],
            documents=[RenderedDocument(
                "http://127.0.0.1/spa",
                '<form action="/search"><input name="q" value="hello"></form>',
            )],
            requests=3,
            actions=2,
            blocked=1,
        )

        async def exercise():
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("browser-test", "http://127.0.0.1/", "balanced")
            scope = ScopePolicy(result.target, allow_private=True)
            with patch("apocalypse.engine.discover_with_browser", AsyncMock(return_value=discovery)):
                urls, forms = await engine._browser_discovery(scope, PROFILES["balanced"], result, {})
            return result, urls, forms

        result, urls, forms = asyncio.run(exercise())
        self.assertEqual(result.stats.requests, 3)
        self.assertEqual(result.stats.pages, 1)
        self.assertEqual(urls, ["http://127.0.0.1/spa"])
        self.assertEqual(forms[0].inputs[0]["name"], "q")

    def test_coverage_separates_http_and_browser_discovery(self):
        discovery = BrowserDiscovery(
            urls=["http://127.0.0.1/", "http://127.0.0.1/spa", "http://127.0.0.1/api/items"],
            documents=[RenderedDocument("http://127.0.0.1/spa", "<a href='/spa'>SPA</a>")],
            requests=2,
        )

        def respond(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200, text='<a href="/about">About</a>',
                    headers={"content-type": "text/html"}, request=request,
                )
            return httpx.Response(200, text="<p>ok</p>", headers={"content-type": "text/html"}, request=request)

        async def exercise() -> ScanResult:
            with tempfile.TemporaryDirectory() as tmp:
                storage = Storage(Path(tmp) / "coverage.db")
                engine = ScanEngine(storage)
                result = engine.queue("http://127.0.0.1/", "safe")
                with patch("apocalypse.engine.discover_with_browser", AsyncMock(return_value=discovery)):
                    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                        scope = ScopePolicy(result.target, allow_private=True)
                        result.status = "running"
                        http_discovered = {scope.target}
                        browser_urls, _ = await engine._browser_discovery(
                            scope, PROFILES["safe"], result, {},
                        )
                        browser_discovered = set(browser_urls)
                        await engine._crawl(
                            client, scope, RateLimiter(1_000_000), PROFILES["safe"], result,
                            authenticated=False, seed_urls=browser_urls, discovered_http=http_discovered,
                        )
                        result.stats.discovered_http = len(http_discovered)
                        result.stats.discovered_browser = len(browser_discovered)
                        result.stats.discovered = len(http_discovered | browser_discovered)
                        result.status = "completed"
                        storage.update_scan(result)
                        loaded = storage.get_scan(result.scan_id)
                        assert loaded is not None
                        self.assertEqual(loaded["discovered_http"], result.stats.discovered_http)
                        self.assertEqual(loaded["discovered_browser"], result.stats.discovered_browser)
                        self.assertIn("http://127.0.0.1/about", http_discovered)
                        self.assertIn("http://127.0.0.1/api/items", browser_discovered)
                        return result

        result = asyncio.run(exercise())
        self.assertGreaterEqual(result.stats.discovered_browser, 2)
        self.assertGreaterEqual(result.stats.discovered_http, 2)
        self.assertGreaterEqual(result.stats.discovered, result.stats.discovered_http)
        self.assertGreaterEqual(result.stats.discovered, result.stats.discovered_browser)


class ProbeTests(unittest.TestCase):
    def test_custom_headers_validate_and_reject_routing_headers(self):
        self.assertEqual(parse_header_lines(["Authorization: Bearer abc"])["Authorization"], "Bearer abc")
        with self.assertRaises(ValueError):
            validate_custom_headers({"Host": "other.example"})
        with self.assertRaises(ValueError):
            validate_custom_headers({"X-Test": "bad\r\nInjected: yes"})

    def test_probe_inventory_skips_sensitive_fields_and_gates_post(self):
        form = FormInfo(
            source_url="https://app.example.com/profile", action="https://app.example.com/update", method="POST",
            inputs=[
                {"name": "display_name", "type": "text", "value": "A"},
                {"name": "csrf_token", "type": "hidden", "value": "secret"},
                {"name": "password", "type": "password", "value": ""},
            ],
        )
        urls = ["https://app.example.com/search?q=one&access_token=secret"]
        without_post = collect_probe_points(urls, [form], include_post=False)
        self.assertEqual([(p.method, p.parameter) for p in without_post], [("GET", "q")])
        with_post = collect_probe_points(urls, [form], include_post=True)
        self.assertEqual([(p.method, p.parameter) for p in with_post], [("GET", "q"), ("POST", "display_name")])

    def test_active_probes_cover_query_and_opted_in_post_form(self):
        requests: list[tuple[str, str]] = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append((request.method, str(request.url)))
            if request.method == "POST":
                values = dict(parse_qsl(request.content.decode()))
                reflected = values.get("display_name", "")
            else:
                reflected = request.url.params.get("q", "")
            headers = {"content-type": "text/html"}
            if request.headers.get("origin"):
                headers["access-control-allow-origin"] = request.headers["origin"]
            return httpx.Response(200, text=f"<p>{reflected}</p>", headers=headers, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type] - storage is unused by this focused test
            result = ScanResult("12345678abcdef00", "http://127.0.0.1/", "deep")
            result.crawled_urls = ["http://127.0.0.1/search?q=hello"]
            form = FormInfo(
                source_url=result.target, action="http://127.0.0.1/profile", method="POST",
                inputs=[{"name": "display_name", "type": "text", "value": "A"}],
            )
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["deep"], result, [form], include_post=True,
                )
            return result

        result = asyncio.run(exercise())
        self.assertEqual(
            sum(item.rule_id == "xss.reflected-unencoded" for item in result.findings), 2,
            msg=f"findings={[(item.rule_id, item.evidence) for item in result.findings]} requests={requests}",
        )
        xss = [item for item in result.findings if item.rule_id == "xss.reflected-unencoded"]
        self.assertTrue(all(item.verified for item in xss))
        self.assertTrue(all(item.evidence.get("reflection_context") for item in xss))
        self.assertTrue(all(item.evidence.get("execution_confirmed") is False for item in xss))
        cors = next(item for item in result.findings if item.rule_id == "cors.origin-reflection")
        self.assertTrue(cors.verified)
        self.assertIn("POST", {method for method, _ in requests})


class OpenAPITests(unittest.TestCase):
    def test_openapi_three_discovers_get_with_refs_and_examples(self):
        document = {
            "openapi": "3.0.3",
            "servers": [{"url": "/api"}],
            "components": {
                "parameters": {
                    "UserId": {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "example": 7}}
                }
            },
            "paths": {
                "/users/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/UserId"}],
                    "get": {"parameters": [{"name": "verbose", "in": "query", "schema": {"type": "boolean"}}]},
                    "delete": {},
                }
            },
        }
        urls = discover_openapi_urls(document, "https://app.example.com/openapi.json", "https://app.example.com/")
        self.assertEqual(urls, ["https://app.example.com/api/users/7?verbose=false"])

    def test_swagger_two_uses_base_path_and_skips_mutating_operations(self):
        document = {
            "swagger": "2.0", "basePath": "/v1",
            "paths": {
                "/search": {
                    "get": {"parameters": [{"name": "q", "in": "query", "type": "string"}]},
                    "post": {"parameters": [{"name": "q", "in": "formData", "type": "string"}]},
                }
            },
        }
        urls = discover_openapi_urls(document, "https://api.example.com/swagger.json", "https://api.example.com/")
        self.assertEqual(urls, ["https://api.example.com/v1/search?q=apocalypse"])

    def test_non_openapi_document_is_rejected(self):
        with self.assertRaises(OpenAPIError):
            discover_openapi_urls({"paths": {}}, "https://app.example.com/spec.json", "https://app.example.com/")

    def test_openapi_operations_include_json_search_body(self):
        document = {
            "openapi": "3.0.0",
            "paths": {
                "/search": {
                    "post": {
                        "operationId": "searchItems",
                        "tags": ["search"],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "q": {"type": "string"},
                                            "page": {"type": "integer"},
                                        },
                                    }
                                }
                            }
                        },
                    }
                },
                "/items/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "schema": {"type": "string"}},
                            {"name": "filter", "in": "query", "schema": {"type": "string"}},
                        ]
                    }
                },
            },
        }
        ops = discover_openapi_operations(document, "https://app.example.com/openapi.json", "https://app.example.com/")
        self.assertTrue(any(op["method"] == "POST" and op["json_fields"] for op in ops))
        self.assertTrue(any(op["method"] == "GET" and any(n == "filter" for n, _ in op["query"]) for op in ops))


class CheckTests(unittest.TestCase):
    def test_header_checks(self):
        response = httpx.Response(200, headers={"Server": "nginx/1.20"}, request=httpx.Request("GET", "https://example.com"))
        findings = analyze_headers("https://example.com/", response)
        rules = {item.rule_id for item in findings}
        self.assertIn("header.missing.content-security-policy", rules)
        self.assertIn("banner.server-version", rules)

    def test_secrets_are_fingerprinted(self):
        body = "const key='AKIAABCDEFGHIJKLMNOP';"
        findings = analyze_body("https://example.com/app.js", body, [], [])
        self.assertEqual(findings[0].rule_id, "secret.aws-access-key")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", repr(findings[0].evidence))


class ContextTests(unittest.TestCase):
    def test_reflection_contexts_are_classified(self):
        marker = 'apocalypse_ab"><apocalypse>'
        self.assertEqual(classify_reflection(f"<p>{marker}</p>", marker).kind, "html_text")
        self.assertEqual(classify_reflection(f'<img alt="{marker}">', marker).kind, "attribute_double")
        self.assertEqual(classify_reflection(f"<script>var x='{marker}';</script>", marker).kind, "javascript")
        self.assertEqual(classify_reflection(f'<div onclick="{marker}">x</div>', marker).kind, "event_handler")
        self.assertEqual(classify_reflection(f"<!-- {marker} -->", marker).kind, "html_comment")


class BaselineTests(unittest.TestCase):
    def test_compare_findings_new_fixed_recurring(self):
        previous = [
            Finding("r1", "A", "high", "high", "https://app.example.com/a", "d", {"parameter": "q"}),
            Finding("r2", "B", "medium", "medium", "https://app.example.com/b", "d", {"parameter": "id"}),
        ]
        current = [
            Finding("r1", "A", "high", "high", "https://app.example.com/a", "d", {"parameter": "q"}),
            Finding("r3", "C", "low", "low", "https://app.example.com/c", "d", {"parameter": "x"}),
        ]
        comparison = compare_findings(current, previous, baseline_scan_id="base1")
        self.assertEqual(comparison.summary, {"new": 1, "fixed": 1, "recurring": 1})
        self.assertEqual(comparison.new, [finding_fingerprint(current[1])])
        self.assertEqual(comparison.fixed, [finding_fingerprint(previous[1])])

    def test_engine_attaches_baseline_against_previous_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "base.db")
            first = ScanResult("scan-old", "https://example.com/", "safe")
            storage.create_scan(first)
            first.status = "completed"
            first.findings = [Finding("r1", "Old", "high", "high", first.target, "d", {"parameter": "q"})]
            storage.replace_findings(first.scan_id, first.findings)
            storage.update_scan(first)

            engine = ScanEngine(storage)
            second = ScanResult("scan-new", "https://example.com/", "safe")
            second.findings = [
                Finding("r1", "Old", "high", "high", second.target, "d", {"parameter": "q"}),
                Finding("r2", "New", "medium", "medium", second.target, "d", {"parameter": "id"}),
            ]
            second.baseline = engine._baseline_for(second)
            self.assertEqual(second.baseline["baseline_scan_id"], "scan-old")
            self.assertEqual(second.baseline["summary"]["new"], 1)
            self.assertEqual(second.baseline["summary"]["recurring"], 1)
            self.assertEqual(second.baseline["summary"]["fixed"], 0)


class AuthSessionTests(unittest.TestCase):
    def test_session_expiry_after_authenticated_success(self):
        def respond(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path in {"", "/"}:
                return httpx.Response(
                    200, text='<a href="/dash">D</a>', headers={"content-type": "text/html"}, request=request,
                )
            if path == "/dash":
                return httpx.Response(302, headers={"location": "/login"}, request=request)
            return httpx.Response(
                200, text='<form method="post"><input type="password" name="p"></form>',
                headers={"content-type": "text/html"}, request=request,
            )

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("authsess01", "http://127.0.0.1/", "safe")
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._crawl(
                    client, scope, RateLimiter(1_000_000), PROFILES["safe"], result,
                    authenticated=True, seed_urls=["http://127.0.0.1/dash"],
                )
            return result

        result = asyncio.run(exercise())
        rules = {item.rule_id for item in result.findings}
        self.assertIn("auth.session-expired", rules)
        self.assertIn("auth.login-form-observed", rules)


class GraphQLTests(unittest.TestCase):
    def test_introspection_extracts_query_fields(self):
        document = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "Query",
                            "fields": [
                                {"name": "viewer", "args": []},
                                {
                                    "name": "user",
                                    "args": [{
                                        "name": "id",
                                        "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                                    }],
                                },
                            ],
                        }
                    ],
                }
            }
        }
        operations, summary = parse_introspection(document)
        self.assertEqual(summary["field_count"], 2)
        self.assertTrue(any("user(id:" in item for item in operations))
        self.assertTrue(summary["introspection_enabled"])

    def test_non_introspection_payload_rejected(self):
        with self.assertRaises(GraphQLError):
            parse_introspection({"data": {}})


class InjectTests(unittest.TestCase):
    def test_sql_and_command_error_fingerprints(self):
        self.assertIsNotNone(detect_sql_error("Error: You have an error in your SQL syntax; check the manual"))
        self.assertIsNotNone(detect_command_error("sh: apocalypse: command not found"))
        self.assertTrue(looks_injection_parameter("id"))
        self.assertFalse(looks_injection_parameter("csrf_token"))

    def test_injection_probe_emits_verified_sqli_finding(self):
        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("id", "")
            if "'" in value or '"' in value:
                text = "You have an error in your SQL syntax near apocalypse"
            else:
                text = "<p>ok</p>"
            return httpx.Response(200, text=text, headers={"content-type": "text/html"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("injec001abcdef00", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/item?id=1"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result, [], include_post=False,
                )
            return result

        result = asyncio.run(exercise())
        sqli = next(item for item in result.findings if item.rule_id == "sqli.error-based")
        self.assertTrue(sqli.verified)
        self.assertFalse(sqli.evidence.get("data_extraction_attempted"))


class LoginFlowTests(unittest.TestCase):
    def test_login_flow_expands_env_and_rejects_bad_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "login.json"
            path.write_text(json.dumps({
                "start_url": "https://app.example.com/login",
                "success_url_contains": "/home",
                "steps": [
                    {"action": "fill", "selector": "#password", "value": "${APOCALYPSE_TEST_SECRET}", "secret": True},
                    {"action": "click", "selector": "button"},
                ],
            }), encoding="utf-8")
            os.environ["APOCALYPSE_TEST_SECRET"] = "s3cret"
            try:
                flow = load_login_flow(path)
            finally:
                os.environ.pop("APOCALYPSE_TEST_SECRET", None)
            self.assertEqual(flow.steps[0].value, "s3cret")
            self.assertTrue(flow.steps[0].secret)

    def test_login_password_override_without_environ(self):
        from apocalypse.login import normalize_login_secrets, parse_login_flow_document

        secrets = normalize_login_secrets(None, login_password="pw-from-ui")
        self.assertEqual(secrets["APOCALYPSE_PASSWORD"], "pw-from-ui")
        flow = parse_login_flow_document({
            "start_url": "https://app.example.com/login",
            "steps": [
                {"action": "fill", "selector": "#password", "value": "${APOCALYPSE_PASSWORD}", "secret": True},
            ],
        }, secret_overrides=secrets)
        self.assertEqual(flow.steps[0].value, "pw-from-ui")


class PolicyAuthzReportTests(unittest.TestCase):
    def test_policy_filters_rules_paths_and_params(self):
        policy = parse_policy_document({
            "disabled_rules": ["banner.server-version"],
            "exclude_paths": ["/health", "/static/*"],
            "exclude_params": ["utm_source"],
        })
        findings = [
            Finding("banner.server-version", "t", "info", "high", "https://a.example/x", "d"),
            Finding("xss.reflected-unencoded", "t", "high", "high", "https://a.example/health", "d"),
            Finding("sqli.error-based", "t", "high", "high", "https://a.example/q", "d", {"parameter": "utm_source"}),
            Finding("sqli.error-based", "t", "high", "high", "https://a.example/q", "d", {"parameter": "id"}),
        ]
        kept = policy.filter_findings(findings)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].evidence["parameter"], "id")

    def test_idor_scoring_and_candidates(self):
        body = '{"order":1,"total":10}' + ("x" * 40)
        score = score_idor(200, body, 200, body)
        self.assertTrue(score["chain_verified"])
        denied = score_idor(200, body, 403, "no")
        self.assertFalse(denied["differential"])
        selected = select_authz_candidates([
            "https://a.example/users/42",
            "https://a.example/static/app.js",
            "https://a.example/items?id=9",
        ])
        self.assertEqual(len(selected), 2)

    def test_taxonomy_and_sarif(self):
        tax = taxonomy_for("sqli.error-based")
        self.assertEqual(tax["cwe"], "CWE-89")
        finding = Finding("xss.reflected-unencoded", "XSS", "high", "high", "https://a.example/?q=1", "desc")
        annotated = annotate_finding(finding)
        self.assertEqual(annotated["cwe"], "CWE-79")
        sarif = json.loads(render_sarif({
            "id": "scan1", "target": "https://a.example/", "profile": "safe", "status": "completed",
            "findings_list": [annotated],
        }))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "xss.reflected-unencoded")

    def test_authz_probe_emits_idor_finding(self):
        shared = '{"id":1,"email":"a@example.com"}' + ("y" * 40)

        def respond(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=shared, headers={"content-type": "application/json"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("idor001abcdef000", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/users/1"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._authz_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result,
                    primary_headers={"Cookie": "a=1"}, secondary_headers={"Cookie": "b=2"},
                    policy=parse_policy_document({}),
                )
            return result

        result = asyncio.run(exercise())
        finding = next(item for item in result.findings if item.rule_id == "authz.idor-differential")
        self.assertTrue(finding.verified)

    def test_browser_verify_marks_execution(self):
        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("q", "")
            # Unquoted attribute context so the engine treats the reflection as dangerous.
            text = f"<html><body><img alt={value}></body></html>"
            return httpx.Response(200, text=text, headers={"content-type": "text/html"}, request=request)

        async def fake_verify(*args, **kwargs):
            return XssBrowserVerdict(True, dialog_message="APOCALYPSE_XSS_browser", final_url="http://127.0.0.1/")

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("browser01abcdef0", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/search?q=hi"]
            scope = ScopePolicy(result.target, allow_private=True)
            with patch("apocalypse.engine.verify_reflected_xss", AsyncMock(side_effect=fake_verify)):
                async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                    await engine._active_probes(
                        client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result, [],
                        include_post=False, api_probe=False, browser_verify=True,
                    )
            return result

        result = asyncio.run(exercise())
        xss = next(item for item in result.findings if item.rule_id == "xss.reflected-unencoded")
        self.assertTrue(xss.evidence.get("execution_confirmed"))
        self.assertTrue(xss.verified)


class ProbePackTests(unittest.TestCase):
    def test_lfi_and_ssti_scoring(self):
        self.assertEqual(detect_lfi("root:x:0:0:root:/root:/bin/bash\n"), "passwd-root")
        self.assertIsNone(detect_lfi("hello"))
        score = score_ssti("result=49", "result={{7*'7'}}", primary="{{7*7}}", confirm="{{7*'7'}}")
        self.assertTrue(score["chain_verified"])
        weak = score_ssti("49", "also 49", primary="{{7*7}}", confirm="{{7*'7'}}")
        self.assertFalse(weak["chain_verified"])

    def test_oast_listener_records_hits(self):
        hub = OastHub(listen="127.0.0.1:0")
        try:
            self.assertTrue(hub.enabled())
            token = hub.issue("ssrf")
            response = httpx.get(token.http_url, timeout=2.0)
            self.assertEqual(response.status_code, 200)
            hits = asyncio.run(hub.poll(token))
            self.assertEqual(len(hits), 1)
            hub.record_hit(OastHit(token_id=token.id, method="GET", path="/x", remote="1.2.3.4"))
            self.assertGreaterEqual(len(hub.local_hits(token.id)), 2)
        finally:
            hub.close()

    def test_lfi_finding_from_path_parameter(self):
        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("file", "")
            if "etc/passwd" in value:
                text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:\n"
            else:
                text = "ok"
            return httpx.Response(200, text=text, headers={"content-type": "text/plain"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("lfi001abcdef0000", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/view?file=readme"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result, [],
                    include_post=False, api_probe=False,
                )
            return result

        result = asyncio.run(exercise())
        finding = next(item for item in result.findings if item.rule_id == "lfi.path-traversal")
        self.assertTrue(finding.verified)

    def test_ssti_finding_from_template_parameter(self):
        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("template", "")
            if value == "{{7*7}}":
                text = "computed 49"
            else:
                text = f"literal {value}"
            return httpx.Response(200, text=text, headers={"content-type": "text/html"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("ssti001abcdef000", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/render?template=hi"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result, [],
                    include_post=False, api_probe=False,
                )
            return result

        result = asyncio.run(exercise())
        finding = next(item for item in result.findings if item.rule_id == "ssti.template-injection")
        self.assertTrue(finding.verified)

    def test_ssrf_oast_verified(self):
        hub = OastHub(listen="127.0.0.1:0")

        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("url", "")
            if value.startswith("http://"):
                try:
                    httpx.get(value, timeout=1.0)
                except httpx.HTTPError:
                    pass
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("ssrf001abcdef000", "http://127.0.0.1/", "balanced")
            result.crawled_urls = ["http://127.0.0.1/fetch?url=https://example.com/"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["balanced"], result, [],
                    include_post=False, api_probe=False, oast=hub,
                )
            return result

        try:
            result = asyncio.run(exercise())
            finding = next(item for item in result.findings if item.rule_id == "ssrf.oast-callback")
            self.assertTrue(finding.verified)
        finally:
            hub.close()


class BlindInjectTests(unittest.TestCase):
    def test_boolean_chain_scoring(self):
        true_fp = fingerprint_response(200, "row-found-" + ("x" * 40))
        false_fp = fingerprint_response(200, "none")
        again_fp = fingerprint_response(200, "row-found-" + ("x" * 40))
        chain = score_boolean_chain(true_fp, false_fp, again_fp)
        self.assertTrue(chain["chain_verified"])
        self.assertTrue(chain["differential"])
        unstable = score_boolean_chain(true_fp, false_fp, fingerprint_response(200, "different"))
        self.assertFalse(unstable["chain_verified"])
        time_ok = score_time_chain(0.05, 2.1, 2.0)
        self.assertTrue(time_ok["chain_verified"])
        time_bad = score_time_chain(2.0, 2.1, 2.0)
        self.assertFalse(time_bad["chain_verified"])
        t1, t2, t3 = boolean_chain_payloads("m")
        self.assertIn("OR", t1)
        self.assertTrue(t2.endswith("x"))
        self.assertIn("OR '1'='1", t3)

    def test_boolean_differential_finding(self):
        def respond(request: httpx.Request) -> httpx.Response:
            value = request.url.params.get("id", "")
            if "OR '" in value and value.endswith("x"):
                body = "none"
            elif "OR '" in value:
                body = "row-found-" + ("x" * 40)
            elif "'" in value or '"' in value:
                body = "ok"
            else:
                body = "ok"
            return httpx.Response(200, text=body, headers={"content-type": "text/html"}, request=request)

        async def exercise() -> ScanResult:
            engine = ScanEngine(None)  # type: ignore[arg-type]
            result = ScanResult("blind001abcdef00", "http://127.0.0.1/", "deep")
            result.crawled_urls = ["http://127.0.0.1/item?id=1"]
            scope = ScopePolicy(result.target, allow_private=True)
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                await engine._active_probes(
                    client, scope, RateLimiter(1_000_000), PROFILES["deep"], result, [],
                    include_post=False, blind_inject=True,
                )
            return result

        result = asyncio.run(exercise())
        finding = next(item for item in result.findings if item.rule_id == "sqli.boolean-blind")
        self.assertTrue(finding.verified)
        self.assertEqual(finding.evidence.get("exploit_chain"), "boolean-TFT")
        true_p, false_p = boolean_payloads("m")
        self.assertNotEqual(true_p, false_p)
        self.assertTrue(fingerprint_response(200, "a" * 40).differs(fingerprint_response(200, "b")))


class LoginRecorderTests(unittest.TestCase):
    def test_redact_recorded_steps_inserts_goto_and_password_placeholder(self):
        document = _redact_recorded_steps([
            {"action": "fill", "selector": "#email", "value": "a@b.com", "secret": False, "url": "https://app.example.com/login"},
            {"action": "fill", "selector": "#password", "value": "${APOCALYPSE_PASSWORD}", "secret": True, "url": "https://app.example.com/login"},
            {"action": "click", "selector": "button[type=submit]", "url": "https://app.example.com/login"},
            {"action": "done", "url": "https://app.example.com/dashboard"},
        ], "https://app.example.com/login")
        parse_login_flow_document(document, expand_secrets=False)
        self.assertEqual(document["steps"][0]["action"], "goto")
        secret = next(step for step in document["steps"] if step.get("secret"))
        self.assertEqual(secret["value"], "${APOCALYPSE_PASSWORD}")

    def test_redact_checkbox_fill_becomes_click(self):
        document = _redact_recorded_steps([
            {"action": "fill", "selector": "input[type=\"checkbox\"]", "value": "on", "url": "https://app.example.com/login"},
            {"action": "done", "url": "https://app.example.com/home"},
        ], "https://app.example.com/login")
        checkbox = next(step for step in document["steps"] if "checkbox" in str(step.get("selector")))
        self.assertEqual(checkbox["action"], "click")


class SsoTenantTicketTests(unittest.TestCase):
    def test_oidc_tenant_and_ticket_providers(self):
        cfg = validate_oidc_config({
            "issuer": "https://login.example.com",
            "client_id": "apocalypse",
            "redirect_uri": "http://127.0.0.1:8080/api/sso/callback",
        })
        self.assertEqual(cfg["client_secret_env"], "OIDC_CLIENT_SECRET")
        self.assertEqual(tenant_slug("Acme Corp!"), "acme-corp")
        jira = validate_ticket_config("jira", {
            "base_url": "https://company.atlassian.net", "project_key": "SEC",
        })
        self.assertEqual(jira["project_key"], "SEC")
        snow = validate_ticket_config("servicenow", {"base_url": "https://example.service-now.com"})
        self.assertEqual(snow["table"], "incident")
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "tenant.db")
            storage.create_tenant({"id": "t1", "name": "Acme", "slug": "acme", "created_at": "t"})
            self.assertEqual(len(storage.list_tenants()), 2)  # includes default
            storage.set_sso_config(cfg)
            self.assertEqual(storage.get_sso_config()["config"]["client_id"], "apocalypse")
            storage.save_sso_state("st", "nonce", "t1")
            consumed = storage.consume_sso_state("st")
            self.assertEqual(consumed["tenant_id"], "t1")
            self.assertIsNone(storage.consume_sso_state("st"))
            scan = ScanResult("tenantscan01", "https://a.example.com", "safe")
            storage.create_scan(scan, tenant_id="t1")
            self.assertEqual(len(storage.list_scans(tenant_id="t1")), 1)
            self.assertEqual(len(storage.list_scans(tenant_id="other")), 0)
            record, token = create_user_record("bob", "analyst", tenant_id="t1", sso_subject="sub-1")
            record["created_at"] = "t"
            storage.create_user(record)
            auth = storage.authenticate_token(token)
            self.assertEqual(auth["tenant_id"], "t1")
            self.assertEqual(storage.find_user_by_sso_subject("sub-1")["id"], record["id"])


class CampaignTeamTests(unittest.TestCase):
    def test_campaign_and_team_ticket_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "camp.db")
            campaign = create_campaign(storage, CampaignSpec(
                name="batch", targets=["https://a.example.com/", "https://b.example.com/"], profile="safe",
            ))
            loaded = storage.get_campaign(campaign["id"])
            self.assertEqual(len(loaded["targets"]), 2)
            record, token = create_user_record("alice", "admin")
            record["created_at"] = "2026-01-01T00:00:00+00:00"
            storage.create_user(record)
            self.assertTrue(role_allows("admin", "analyst"))
            self.assertIsNotNone(storage.authenticate_token(token))
            flow = parse_login_flow_document({
                "start_url": "https://a.example.com/login",
                "steps": [{"action": "click", "selector": "button"}],
            }, expand_secrets=False)
            storage.save_login_flow({
                "id": "flow1", "name": "login", "flow": {
                    "start_url": flow.start_url, "steps": [{"action": "click", "selector": "button"}],
                }, "created_at": "t", "updated_at": "t",
            })
            self.assertEqual(storage.get_login_flow("flow1")["name"], "login")
            self.assertEqual(storage.unique_login_flow_name("login"), "login-2")
            self.assertEqual(storage.unique_login_flow_name("login", exclude_id="flow1"), "login")
            storage.save_login_flow({
                "id": "flow2", "name": storage.unique_login_flow_name("login"), "flow": {
                    "start_url": flow.start_url, "steps": [{"action": "click", "selector": "button"}],
                }, "created_at": "t", "updated_at": "t",
            })
            self.assertTrue(storage.delete_login_flow("flow2"))
            self.assertIsNone(storage.get_login_flow("flow2"))
            cfg = validate_ticket_config("github", {"repo": "acme/app", "token_env": "GITHUB_TOKEN"})
            storage.set_ticket_config("github", cfg)
            finding = Finding("r1", "Title", "high", "high", "https://a.example.com/", "d", {"parameter": "id"})
            key = finding_ticket_key("scan1", finding)
            storage.upsert_ticket({
                "id": "t1", "finding_key": key, "scan_id": "scan1", "rule_id": "r1", "title": "Title",
                "severity": "high", "provider": "github", "external_id": "1",
                "external_url": "https://github.com/acme/app/issues/1", "status": "open",
                "created_at": "t", "last_sync_at": "t", "meta": {},
            })
            self.assertEqual(storage.list_tickets()[0]["external_id"], "1")


class WebhookScheduleTests(unittest.TestCase):
    def test_webhook_payload_omits_raw_secrets(self):
        result = ScanResult("wh1", "https://example.com", "safe")
        result.status = "completed"
        result.findings.append(Finding(
            "r1", "Title", "high", "high", result.target, "d",
            evidence={"parameter": "q"},
        ))
        payload = scan_webhook_payload(result)
        self.assertEqual(payload["event"], "scan.completed")
        self.assertNotIn("Cookie", json.dumps(payload))
        self.assertEqual(payload["findings"][0]["severity"], "high")
        self.assertEqual(validate_webhook_url("https://hooks.example.com/x"), "https://hooks.example.com/x")
        with self.assertRaises(ValueError):
            validate_webhook_url("ftp://hooks.example.com/x")

    def test_schedule_persists_and_fail_on_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "sched.db")
            item = create_schedule(
                storage, target="https://example.com/", profile="safe", interval_minutes=60, graphql=True,
            )
            self.assertEqual(storage.list_schedules()[0]["id"], item["id"])
            self.assertTrue(storage.delete_schedule(item["id"]))
        findings = [Finding("r1", "t", "medium", "high", "https://example.com/", "d")]
        self.assertFalse(should_fail(findings, "high"))
        self.assertTrue(should_fail(findings, "medium"))


class StorageTests(unittest.TestCase):
    def test_scan_roundtrip_and_dashboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.db")
            scan = ScanResult("abc", "https://example.com", "safe")
            storage.create_scan(scan)
            scan.status = "completed"
            scan.findings.append(Finding("r1", "Title", "high", "high", scan.target, "Description"))
            scan.baseline = {"baseline_scan_id": "prev", "summary": {"new": 1, "fixed": 0, "recurring": 0}}
            storage.replace_findings(scan.scan_id, scan.findings)
            storage.update_scan(scan)
            loaded = storage.get_scan("abc")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded["findings_list"][0]["rule_id"], "r1")
            self.assertEqual(loaded["baseline"]["summary"]["new"], 1)
            self.assertEqual(storage.dashboard()["total_findings"], 1)
            self.assertEqual(storage.dashboard()["active_schedules"], 0)


class WebHelpersTests(unittest.TestCase):
    def test_optional_str_rejects_json_null_stringification(self):
        from apocalypse.web import _optional_str

        self.assertIsNone(_optional_str(None))
        self.assertIsNone(_optional_str(""))
        self.assertIsNone(_optional_str("None"))
        self.assertIsNone(_optional_str("null"))
        self.assertEqual(_optional_str("flow-1"), "flow-1")


class ReportI18nTests(unittest.TestCase):
    def test_html_report_zh_and_lang_query(self):
        scan = {
            "id": "abc123",
            "target": "https://example.com/",
            "status": "completed",
            "profile": "safe",
            "discovered": 1,
            "discovered_http": 1,
            "discovered_browser": 0,
            "errors": [],
            "baseline": {},
            "findings_list": [],
        }
        zh = render_html(scan, lang="zh")
        en = render_html(scan, lang="en")
        self.assertIn("评估报告", zh)
        self.assertIn("暂无漏洞记录", zh)
        self.assertIn("assessment report", en)
        self.assertIn("No findings recorded", en)
        self.assertEqual(lang_from_request("/reports/abc.html?lang=zh"), "zh")
        self.assertEqual(lang_from_request("/reports/abc.html", "zh-CN,zh;q=0.9"), "zh")


if __name__ == "__main__":
    unittest.main()
