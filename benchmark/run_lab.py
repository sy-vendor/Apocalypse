#!/usr/bin/env python3
"""Run the reviewed, local-only HTTP vulnerability benchmark."""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import sys
import tempfile
import threading
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from apocalypse.engine import PROFILES, ScanEngine  # noqa: E402
from apocalypse.models import ScanOptions  # noqa: E402
from apocalypse.storage import Storage  # noqa: E402

GROUND_TRUTH = ROOT / "benchmark" / "ground_truth.json"


class LabHandler(BaseHTTPRequestHandler):
    """Deliberately vulnerable application reachable only on loopback."""

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        body, status, extra = self._route(parsed.path, params)
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", extra.pop("Content-Type", "text/html; charset=utf-8"))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        for name, header_value in extra.items():
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _route(self, path: str, params: dict[str, list[str]]) -> tuple[str, int, dict[str, str]]:
        value = lambda name: params.get(name, [""])[0]
        if path == "/":
            links = [
                "/xss?q=hello", "/safe/xss?q=hello", "/sqli?id=1", "/safe/sqli?id=1",
                "/cmd?q=hello", "/file?file=readme.txt", "/template?template=hello",
                "/redirect?next=/home", "/ssrf?url=http://example.invalid/",
                "/secret", "/stack", "/listing", "/cookie", "/cors-wildcard",
                "/login", "/api/users/42",
            ]
            origin = self.headers.get("Origin")
            headers = {"Access-Control-Allow-Origin": origin} if origin else {}
            return "".join(f'<a href="{link}">{link}</a>' for link in links), 200, headers
        if path == "/xss":
            return f"<main>{value('q')}</main>", 200, {}
        if path == "/safe/xss":
            return f"<main>{html.escape(value('q'), quote=True)}</main>", 200, {}
        if path == "/sqli":
            text = value("id")
            body = "You have an error in your SQL syntax" if "'" in text or '"' in text else "record 1"
            return body, 200, {}
        if path == "/safe/sqli":
            return f"record {html.escape(value('id'))}", 200, {}
        if path == "/cmd":
            text = value("q")
            vulnerable = ";apocalypse" in text or "|apocalypse" in text
            return ("sh: apocalypse: command not found" if vulnerable else html.escape(text)), 200, {}
        if path == "/file":
            text = value("file")
            if ".." in text or "/etc/passwd" in text or "win.ini" in text.lower():
                return "root:x:0:0:root:/root:/bin/bash\n", 200, {}
            return "public readme", 200, {}
        if path == "/template":
            text = value("template")
            return ("49" if text == "{{7*7}}" else html.escape(text)), 200, {}
        if path == "/redirect":
            destination = value("next") or "/"
            if urlsplit(destination).hostname == "apocalypse.invalid":
                return "redirect", 302, {"Location": destination}
            return "redirect preview", 200, {}
        if path == "/ssrf":
            target = value("url")
            if urlsplit(target).hostname == "127.0.0.1":
                try:
                    with urllib.request.urlopen(target, timeout=2) as response:  # noqa: S310 - loopback fixture
                        response.read(128)
                except OSError:
                    pass
            return "fetch complete", 200, {}
        if path == "/secret":
            return "debug credential: AKIAABCDEFGHIJKLMNOP", 200, {}
        if path == "/stack":
            return "Traceback (most recent call last):\nValueError: deliberate lab error", 200, {}
        if path == "/listing":
            return "<title>Index of /uploads</title><h1>Index of /uploads</h1>", 200, {}
        if path == "/cookie":
            return "cookie", 200, {"Set-Cookie": "session=fixture"}
        if path == "/cors-wildcard":
            return "public data", 200, {"Access-Control-Allow-Origin": "*"}
        if path == "/login":
            form = '<form method="post" action="http://127.0.0.1/login"><input type="password" name="password"></form>'
            return form, 200, {}
        if path == "/api/users/42":
            return '{"id":42,"email":"victim@example.test","role":"user"}', 200, {"Content-Type": "application/json"}
        if path == "/home":
            return "home", 200, {}
        return "not found", 404, {}


def load_ground_truth() -> dict:
    document = json.loads(GROUND_TRUTH.read_text())
    if document.get("schema") != 1 or not document.get("cases"):
        raise ValueError("ground truth must use schema 1 and contain cases")
    ids: set[str] = set()
    for case in document["cases"]:
        required = {"id", "rule_id", "path", "expected", "family", "review"}
        if required - set(case):
            raise ValueError(f"ground-truth case missing fields: {case}")
        if case["id"] in ids:
            raise ValueError(f"duplicate ground-truth id: {case['id']}")
        ids.add(case["id"])
        if case["expected"] not in {"positive", "negative"}:
            raise ValueError(f"invalid expectation: {case['id']}")
        if case["review"].get("status") != "approved":
            raise ValueError(f"case is not approved: {case['id']}")
    return document


def score(findings: list[dict], truth: dict) -> dict:
    cases = truth["cases"]
    expected = {(case["rule_id"], case["path"]) for case in cases if case["expected"] == "positive"}
    reviewed_locations = {(case["rule_id"], case["path"]) for case in cases}
    evaluated_rules = {case["rule_id"] for case in cases}
    observed = {
        (item["rule_id"], urlsplit(item["url"]).path)
        for item in findings if item["rule_id"] in evaluated_rules
    }
    tp, fp, fn = expected & observed, observed - expected, expected - observed
    precision = len(tp) / (len(tp) + len(fp)) if tp or fp else 0.0
    recall = len(tp) / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    families: dict[str, dict[str, int | float]] = {}
    for family in sorted({case["family"] for case in cases}):
        family_cases = [case for case in cases if case["family"] == family]
        family_expected = {(case["rule_id"], case["path"]) for case in family_cases if case["expected"] == "positive"}
        family_locations = {(case["rule_id"], case["path"]) for case in family_cases}
        family_observed = observed & family_locations
        ft = family_expected & family_observed
        ff = family_observed - family_expected
        fnn = family_expected - family_observed
        families[family] = {"tp": len(ft), "fp": len(ff), "fn": len(fnn), "cases": len(family_cases)}
    return {
        "ground_truth_version": truth["version"], "ground_truth_cases": len(cases),
        "reviewed_locations": len(reviewed_locations), "evaluated_rules": sorted(evaluated_rules),
        "expected": sorted([list(x) for x in expected]), "observed": sorted([list(x) for x in observed]),
        "false_positive_items": sorted([list(x) for x in fp]),
        "false_negative_items": sorted([list(x) for x in fn]),
        "true_positives": len(tp), "false_positives": len(fp), "false_negatives": len(fn),
        "precision": precision, "recall": recall, "f1": f1, "families": families,
    }


async def run() -> dict:
    truth = load_ground_truth()
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = PROFILES["balanced"]
    PROFILES["balanced"] = replace(original, requests_per_second=1_000.0)
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "benchmark.db")
            engine = ScanEngine(storage)
            result = engine.queue(target, "balanced")
            options = ScanOptions(
                oast_listen="127.0.0.1:0", custom_headers={"Cookie": "session=reviewer-a"},
                secondary_headers={"Cookie": "session=reviewer-b"},
            )
            await engine.run(result, allow_private=True, options=options)
            metrics = score([item.to_dict() for item in result.findings], truth)
            return {
                "schema": 2, "generated_at": datetime.now(timezone.utc).isoformat(),
                "profile": "balanced", "target": "loopback-reviewed-lab",
                "scan_status": result.status, "requests": result.stats.requests,
                "scanner_errors": result.errors, **metrics,
            }
    finally:
        PROFILES["balanced"] = original
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--min-precision", type=float, default=0.90)
    args = parser.parse_args()
    result = asyncio.run(run())
    output = ROOT / "benchmark" / "results" / "latest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if result["scan_status"] != "completed" or result["scanner_errors"]:
        raise SystemExit("benchmark scan failed or reported scanner errors")
    if result["recall"] < args.min_recall or result["precision"] < args.min_precision:
        raise SystemExit("benchmark quality gate failed")


if __name__ == "__main__":
    main()
