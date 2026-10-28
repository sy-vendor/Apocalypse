from __future__ import annotations

import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from apocalypse.engine import ScanEngine
from apocalypse.storage import Storage
from apocalypse.web import make_handler


@unittest.skipUnless(os.environ.get("APOCALYPSE_E2E") == "1", "set APOCALYPSE_E2E=1")
class ConsoleBrowserE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import Error as PlaywrightError, sync_playwright
        except ImportError as exc:  # pragma: no cover - explicit setup failure in E2E job
            raise unittest.SkipTest("install Apocalypse with the dev extra") from exc
        cls._tmp = tempfile.TemporaryDirectory()
        storage = Storage(Path(cls._tmp.name) / "e2e.db")
        cls._server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(storage, ScanEngine(storage)))
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls.base_url = f"http://127.0.0.1:{cls._server.server_port}"
        cls._playwright = sync_playwright().start()
        try:
            cls._browser = cls._playwright.chromium.launch(headless=True)
        except PlaywrightError:
            # Developer machines commonly have Chrome but not Playwright's
            # downloaded Chromium. CI installs Chromium explicitly.
            cls._browser = cls._playwright.chromium.launch(channel="chrome", headless=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._browser.close()
        cls._playwright.stop()
        cls._server.shutdown()
        cls._server.server_close()
        cls._thread.join(timeout=2)
        cls._tmp.cleanup()

    def test_dashboard_navigation_language_and_scan_validation(self) -> None:
        page = self._browser.new_page()
        page.goto(self.base_url, wait_until="networkidle")
        self.assertEqual(page.title(), "Apocalypse")
        page.locator('[data-view="findings"]').click()
        self.assertTrue(page.locator("#findings-view").evaluate("el => el.classList.contains('active')"))
        page.locator("#lang-en").click()
        self.assertEqual(page.locator("#page-title").inner_text(), "Vulnerabilities")
        page.locator('[data-view="quality"]').click()
        self.assertEqual(page.locator("#page-title").inner_text(), "Quality benchmark")
        self.assertEqual(page.locator("#quality-cases").inner_text(), "19")
        self.assertIn("Pending", page.locator("#quality-signoff").inner_text())
        page.locator("#new-scan").click()
        self.assertTrue(page.locator("#scan-dialog").is_visible())
        response = page.request.post(f"{self.base_url}/api/scans", data={
            "target": "not-a-url", "profile": "safe", "acknowledged": True,
        })
        self.assertEqual(response.status, 400)
        self.assertIn("complete http(s) URL", response.json()["error"])
        page.close()
