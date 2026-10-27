import unittest
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sentinel_src.checks import cookie_findings, header_findings
from sentinel_src.config import DEFAULT_USER_AGENT, ScanConfig
from sentinel_src.scanner import redact
from sentinel_src.scope import ScopeError, ScopePolicy, _matches
from sentinel_src.authz import (
    fingerprint_body,
    judge_cross_access,
    load_auth_file,
    load_authz_checks,
    parse_manual_review,
    structures_similar,
)
from sentinel_src.batch import load_targets, result_filename
from sentinel_src.cli import parse_interval, write_inbox
from sentinel_src.discovery import discover_urls, passive_findings
from sentinel_src.programs import PROGRAMS
from sentinel_src.report import build_inbox, markdown_report, submission_bundle


class ScopeTests(unittest.TestCase):
    def test_exact_and_wildcard_matching(self):
        self.assertTrue(_matches("api.example.com", "*.example.com"))
        self.assertFalse(_matches("example.com", "*.example.com"))
        self.assertFalse(_matches("evil-example.com", "*.example.com"))

    def test_rejects_out_of_scope_without_dns(self):
        policy = ScopePolicy(("example.com",))
        with self.assertRaises(ScopeError):
            policy.validate_url("https://other.example/", resolve_dns=False)

    def test_rejects_credentials_and_http(self):
        policy = ScopePolicy(("example.com",))
        with self.assertRaises(ScopeError):
            policy.validate_url("https://user:pass@example.com/", resolve_dns=False)
        with self.assertRaises(ScopeError):
            policy.validate_url("http://example.com/", resolve_dns=False)

    def test_batch_manifest_deduplicates_and_rejects_scope_escape(self):
        config = ScanConfig(scope=ScopePolicy(("example.com",)))
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as handle:
            handle.write("# authorized\nhttps://example.com/\nhttps://example.com/\n")
            handle.flush()
            self.assertEqual(load_targets(Path(handle.name), config), ["https://example.com/"])
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as handle:
            handle.write("https://outside.example/\n")
            handle.flush()
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_targets(Path(handle.name), config)

    def test_batch_result_filename_is_stable(self):
        self.assertEqual(result_filename("https://example.com/"), result_filename("https://example.com/"))
        self.assertTrue(result_filename("https://example.com/").startswith("example.com-"))


class CheckTests(unittest.TestCase):
    def test_missing_headers(self):
        findings = header_findings("https://example.com", {})
        self.assertTrue(any(f.id == "missing-content-security-policy" for f in findings))
        self.assertTrue(all(not finding.submittable for finding in findings))

    def test_cookie_flags(self):
        findings = cookie_findings("https://example.com", ["session=abc; Path=/"])
        self.assertEqual(findings[0].evidence["missing"], ["Secure", "HttpOnly", "SameSite"])

    def test_redaction(self):
        self.assertNotIn("supersecret", redact("Authorization: supersecret"))
        self.assertNotIn("abc123", redact("api_key=abc123"))

    def test_default_user_agent_is_text(self):
        self.assertIsInstance(DEFAULT_USER_AGENT, str)

    def test_program_exclusions_load(self):
        content = b'''[scope]\nallow_hosts=["example.com"]\n[scan]\nexcluded_finding_ids=["missing-content-security-policy"]\n'''
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(content)
            handle.flush()
            config = ScanConfig.load(Path(handle.name))
        self.assertEqual(config.excluded_finding_ids, ("missing-content-security-policy",))

    def test_bestpay_policy_disables_automation(self):
        config = ScanConfig.load(Path("examples/bestpay-visible-scope.toml"))
        self.assertFalse(config.automation_allowed)
        self.assertFalse(config.crawl_enabled)
        self.assertEqual(config.concurrency, 1)

    def test_vala_policy_blocks_bulk_during_shanghai_work_hours(self):
        config = ScanConfig.load(Path("examples/vala-visible-scope.toml"))
        self.assertTrue(config.automation_allowed)
        self.assertEqual(config.requests_per_second, 0.2)
        # 03:00 UTC is 11:00 in Asia/Shanghai.
        day = datetime(2026, 10, 27, 3, tzinfo=timezone.utc)
        self.assertTrue(config.bulk_automation_blocked(day))
        self.assertGreater(config.seconds_until_bulk_allowed(day), 0)
        # 14:00 UTC is 22:00 in Asia/Shanghai.
        night = datetime(2026, 10, 27, 14, tzinfo=timezone.utc)
        self.assertFalse(config.bulk_automation_blocked(night))
        self.assertEqual(config.seconds_until_bulk_allowed(night), 0)
        self.assertIn("vala", PROGRAMS)
        self.assertTrue(PROGRAMS["vala"].config.exists())

    def test_report_requires_human_evidence(self):
        data = {"target": "https://example.com", "findings": [{
            "title": "test", "url": "https://example.com/path", "evidence": {}
        }]}
        report = markdown_report(data)
        self.assertIn("完整 POC", report)
        self.assertIn("关键步骤与结果截图", report)
        self.assertIn("人工验证声明", report)
        bundle = submission_bundle(data)
        self.assertFalse(bundle["platform_submission_enabled"])
        self.assertTrue(any("WebShell" in item for item in bundle["checklist"]))
        self.assertEqual(bundle["findings"], [])

    def test_discovery_stays_on_host_and_skips_risky_urls(self):
        body = '''<a href="/safe">safe</a><a href="/logout">logout</a>
        <a href="/search?q=x">query</a><a href="https://outside.example/x">outside</a>
        <script src="/app.js"></script>'''
        urls = discover_urls("https://example.com/start", "text/html", body)
        self.assertEqual(urls, ["https://example.com/app.js", "https://example.com/safe"])

    def test_passive_evidence_is_fingerprinted(self):
        findings = passive_findings("https://example.com/app.js", "const x='AKIAABCDEFGHIJKLMNOP'; host='10.2.3.4'")
        self.assertEqual({finding.id for finding in findings}, {"cloud-access-key", "private-address-disclosure"})
        encoded = str([finding.evidence for finding in findings])
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", encoded)
        self.assertNotIn("10.2.3.4", encoded)
        self.assertTrue(all(not finding.submittable for finding in findings))
        self.assertTrue(all(finding.suspicious for finding in findings))

    def test_parse_interval(self):
        self.assertEqual(parse_interval("90"), 90)
        self.assertEqual(parse_interval("5m"), 300)
        self.assertEqual(parse_interval("1h"), 3600)
        with self.assertRaises(Exception):
            parse_interval("30s")

    def test_inbox_lists_suspicious_separately(self):
        results = [{
            "target": "https://example.com/",
            "output": "runs/example.json",
            "findings": [
                {"id": "missing-referrer-policy", "title": "header", "submittable": False, "suspicious": False},
                {
                    "id": "cloud-access-key", "title": "key", "submittable": False, "suspicious": True,
                    "url": "https://example.com/app.js", "severity": "medium", "evidence": {},
                    "triage_reason": "review", "description": "signal",
                },
                {
                    "id": "confirmed", "title": "ok", "submittable": True, "suspicious": True,
                    "url": "https://example.com/x", "severity": "high", "evidence": {},
                    "triage_reason": "impact", "description": "impact",
                },
            ],
        }]
        inbox = build_inbox(results, generated_at="2026-01-01T00:00:00+00:00")
        self.assertEqual(inbox["suspicious_count"], 2)
        self.assertEqual(inbox["candidate_count"], 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            written = write_inbox(path, results)
            self.assertEqual(written["suspicious_count"], 2)
            self.assertTrue((path / "suspicious.json").exists())
            self.assertTrue((path / "candidates.json").exists())
            self.assertTrue((path / "suspicious.md").exists())
            md = (path / "suspicious.md").read_text(encoding="utf-8")
            self.assertIn("key", md)
            self.assertIn("可疑发现收件箱", md)

    def test_authz_structures_and_public_endpoint_not_flagged(self):
        owner = fingerprint_body(200, "application/json", '{"id":1,"secret":"x"}')
        cross = fingerprint_body(200, "application/json", '{"id":1,"secret":"y"}')
        anon = fingerprint_body(200, "application/json", '{"id":1,"secret":"z"}')
        self.assertTrue(structures_similar(owner, cross))
        self.assertIsNone(judge_cross_access(
            check_name="public", resource_owner="account_a", url="https://example.com/o/1",
            owner_fp=owner, cross_fp=cross, anon_fp=anon,
        ))

    def test_authz_cross_read_flags_suspicious_and_candidate(self):
        owner = fingerprint_body(200, "application/json", '{"orderId":"a1","amount":12}')
        cross = fingerprint_body(200, "application/json", '{"orderId":"a1","amount":12}')
        anon = fingerprint_body(401, "application/json", '{"error":"auth"}')
        finding = judge_cross_access(
            check_name="order", resource_owner="account_a", url="https://example.com/orders/a1",
            owner_fp=owner, cross_fp=cross, anon_fp=anon,
        )
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertTrue(finding.suspicious)
        self.assertTrue(finding.submittable)
        different = fingerprint_body(200, "application/json", '{"message":"forbidden page"}')
        self.assertFalse(structures_similar(owner, different))
        self.assertIsNone(judge_cross_access(
            check_name="order", resource_owner="account_a", url="https://example.com/orders/a1",
            owner_fp=owner, cross_fp=different, anon_fp=anon,
        ))

    def test_authz_loaders_and_manual_inbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auth = root / "auth.local.toml"
            auth.write_text(
                '[account_a]\ncookie = "a=1"\n[account_b]\nauthorization = "Bearer b"\n',
                encoding="utf-8",
            )
            a, b = load_auth_file(auth)
            self.assertEqual(a.headers["Cookie"], "a=1")
            self.assertEqual(b.headers["Authorization"], "Bearer b")
            checks = root / "checks.toml"
            checks.write_text(
                '[[checks]]\nname="o"\nurl="https://example.com/o/{id}"\nid_a="1"\nid_b="2"\n',
                encoding="utf-8",
            )
            loaded = load_authz_checks(checks)
            self.assertEqual(loaded[0].id_a, "1")
            manual = root / "manual.md"
            manual.write_text(
                "# t\n- 标题：测试越权\n- 严重性：high\n- URL：https://example.com/x\n"
                "- 可提交候选：是\n- 分流原因：人工确认\n- 描述：B可读A订单\n",
                encoding="utf-8",
            )
            payload = parse_manual_review(manual)
            self.assertEqual(len(payload["findings"]), 1)
            self.assertTrue(payload["findings"][0]["submittable"])
            self.assertTrue(payload["findings"][0]["suspicious"])


if __name__ == "__main__":
    unittest.main()
