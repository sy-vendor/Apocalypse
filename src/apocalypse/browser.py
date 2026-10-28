from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .crawler import normalize_candidate


BLOCKED_RESOURCE_TYPES = {"font", "image", "media", "ping", "stylesheet", "texttrack"}
DISCOVERY_RESOURCE_TYPES = {"document", "fetch", "xhr"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
UNSAFE_HREF = ("logout", "signout", "sign-out", "delete", "destroy", "unsubscribe")
ROUTE_HOOK_SCRIPT = """
(() => {
  if (window.__apocalypseHooked) return;
  window.__apocalypseHooked = true;
  window.__apocalypseRoutes = window.__apocalypseRoutes || [];
  const record = () => {
    try { window.__apocalypseRoutes.push(String(location.href)); } catch (_) {}
  };
  const wrap = (fn) => function (...args) {
    const result = fn.apply(this, args);
    record();
    return result;
  };
  history.pushState = wrap(history.pushState.bind(history));
  history.replaceState = wrap(history.replaceState.bind(history));
  window.addEventListener("hashchange", record);
  window.addEventListener("popstate", record);
})();
"""
DOM_URL_SCRIPT = """
() => {
  const urls = new Set();
  const add = (value) => {
    if (typeof value === "string" && value.trim()) urls.add(value.trim());
  };
  for (const el of document.querySelectorAll(
    "a[href], area[href], form[action], link[href], [to], [data-href], [data-url], [data-to], [routerlink]"
  )) {
    add(el.href || el.action || el.getAttribute("href") || el.getAttribute("action")
      || el.getAttribute("to") || el.getAttribute("data-href") || el.getAttribute("data-url")
      || el.getAttribute("data-to") || el.getAttribute("routerlink"));
  }
  for (const value of (window.__apocalypseRoutes || [])) add(value);
  add(location.href);
  return Array.from(urls);
}
"""
CLICKABLE_HREFS_SCRIPT = """
() => Array.from(document.querySelectorAll("a[href]"))
  .map((link) => link.href)
  .filter((href) => typeof href === "string" && href.length > 0)
"""


class BrowserUnavailable(RuntimeError):
    pass


async def launch_chromium(playwright: object, *, headless: bool = True):
    """Prefer the locally installed Google Chrome / Edge, then fall back to Playwright's Chromium.

    Avoids a ~180MB browser download when Chrome is already installed on the machine.
    Override with APOCALYPSE_BROWSER_CHANNEL=chrome|msedge|chromium|bundled
    """
    import os

    preferred = (os.environ.get("APOCALYPSE_BROWSER_CHANNEL") or "").strip().lower()
    channels: list[str | None]
    if preferred == "bundled":
        channels = [None]
    elif preferred in {"chrome", "msedge", "chromium", "chrome-beta", "msedge-beta"}:
        channels = [preferred, None]
    else:
        channels = ["chrome", "msedge", "chromium", None]

    last_error: Exception | None = None
    for channel in channels:
        try:
            kwargs: dict = {"headless": headless}
            if channel:
                kwargs["channel"] = channel
            return await playwright.chromium.launch(**kwargs)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 — try next channel
            last_error = exc
            continue
    raise BrowserUnavailable(
        "Could not launch a browser. Install Google Chrome, or run: python -m playwright install chromium"
        + (f" ({type(last_error).__name__}: {last_error})" if last_error else "")
    )


@dataclass(slots=True)
class RenderedDocument:
    url: str
    html: str


@dataclass(slots=True)
class BrowserDiscovery:
    urls: list[str] = field(default_factory=list)
    documents: list[RenderedDocument] = field(default_factory=list)
    requests: int = 0
    actions: int = 0
    blocked: int = 0
    errors: list[str] = field(default_factory=list)


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, (parsed.hostname or "").lower().rstrip("."), port


def same_origin(candidate: str, target: str) -> bool:
    try:
        return _origin(candidate) == _origin(target)
    except ValueError:
        return False


def normalize_browser_url(base_url: str, candidate: str, target: str) -> str | None:
    normalized = normalize_candidate(base_url, candidate)
    if normalized is None or not same_origin(normalized, target):
        return None
    return normalized


def cookies_from_header(value: str, target: str) -> list[dict[str, str]]:
    target_parts = urlsplit(target)
    origin = urlunsplit((target_parts.scheme, target_parts.netloc, "/", "", ""))
    cookies: list[dict[str, str]] = []
    for part in value.split(";"):
        if "=" not in part:
            continue
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        if not name or name.startswith("$") or any(ch in name for ch in "\r\n\t "):
            continue
        cookies.append({"name": name, "value": cookie_value.strip(), "url": origin})
    return cookies


def _enqueue(url: str, *, discovered: set[str], queue: deque[str]) -> None:
    if url not in discovered:
        discovered.add(url)
        queue.append(url)


def _safe_action_target(base_url: str, candidate: str, target: str) -> str | None:
    lowered = candidate.lower()
    if any(word in lowered for word in UNSAFE_HREF):
        return None
    return normalize_browser_url(base_url, candidate, target)


async def discover_with_browser(
    target: str,
    *,
    custom_headers: dict[str, str],
    max_pages: int,
    max_requests: int,
    max_actions: int = 12,
    navigation_timeout_ms: int = 12_000,
    settle_time_ms: int = 750,
) -> BrowserDiscovery:
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise BrowserUnavailable(
            "browser crawl requires the 'browser' extra and Chromium: "
            "pip install -e '.[browser]' && playwright install chromium"
        ) from exc

    result = BrowserDiscovery()
    if max_pages <= 0 or max_requests <= 0:
        return result

    context_headers = {name: value for name, value in custom_headers.items() if name.lower() != "cookie"}
    cookie_header = next((value for name, value in custom_headers.items() if name.lower() == "cookie"), "")
    discovered: set[str] = {target}
    navigated: set[str] = set()
    queue: deque[str] = deque([target])

    try:
        async with async_playwright() as playwright:
            browser = await launch_chromium(playwright, headless=True)
            context = await browser.new_context(
                accept_downloads=False,
                extra_http_headers=context_headers,
                ignore_https_errors=False,
                service_workers="block",
            )
            if cookie_header:
                cookies = cookies_from_header(cookie_header, target)
                if cookies:
                    await context.add_cookies(cookies)
            await context.add_init_script(ROUTE_HOOK_SCRIPT)

            async def route_request(route: object) -> None:
                request = route.request  # type: ignore[attr-defined]
                url = request.url
                method = request.method.upper()
                resource_type = request.resource_type
                if (
                    method in MUTATING_METHODS
                    or method not in {"GET", "HEAD"}
                    or not same_origin(url, target)
                    or resource_type in BLOCKED_RESOURCE_TYPES
                    or result.requests >= max_requests
                ):
                    result.blocked += 1
                    await route.abort()  # type: ignore[attr-defined]
                    return
                result.requests += 1
                if resource_type in DISCOVERY_RESOURCE_TYPES:
                    normalized = normalize_browser_url(target, url, target)
                    if normalized:
                        discovered.add(normalized)
                await route.continue_()  # type: ignore[attr-defined]

            await context.route("**/*", route_request)
            page = await context.new_page()
            page.set_default_timeout(navigation_timeout_ms)

            async def harvest(base_url: str) -> None:
                for candidate in await page.evaluate(DOM_URL_SCRIPT):
                    normalized = normalize_browser_url(base_url, str(candidate), target)
                    if normalized:
                        _enqueue(normalized, discovered=discovered, queue=queue)

            async def soft_navigate(base_url: str) -> None:
                if result.actions >= max_actions or result.requests >= max_requests:
                    return
                clicked: set[str] = set()
                hrefs = await page.evaluate(CLICKABLE_HREFS_SCRIPT)
                for href in hrefs:
                    if result.actions >= max_actions or result.requests >= max_requests:
                        break
                    normalized = _safe_action_target(base_url, str(href), target)
                    if normalized is None or normalized in navigated or normalized in clicked:
                        continue
                    clicked.add(normalized)
                    before = page.url
                    result.actions += 1
                    try:
                        await page.evaluate(
                            """(targetHref) => {
                              const link = Array.from(document.querySelectorAll("a[href]"))
                                .find((item) => item.href === targetHref);
                              if (link) link.click();
                            }""",
                            href,
                        )
                        await page.wait_for_timeout(settle_time_ms)
                    except PlaywrightError as exc:
                        result.errors.append(f"action {href}: {type(exc).__name__}: {exc}")
                        continue
                    current = page.url
                    if same_origin(current, target):
                        discovered.add(current)
                        await harvest(current)
                        if current != before and current not in navigated and len(navigated) < max_pages:
                            navigated.add(current)
                            result.documents.append(RenderedDocument(current, await page.content()))
                    _enqueue(normalized, discovered=discovered, queue=queue)

            while queue and len(navigated) < max_pages and result.requests < max_requests:
                url = queue.popleft()
                if url in navigated:
                    continue
                navigated.add(url)
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)
                    await page.wait_for_timeout(settle_time_ms)
                    final_url = page.url
                    if not same_origin(final_url, target):
                        continue
                    html = await page.content()
                    result.documents.append(RenderedDocument(final_url, html))
                    discovered.add(final_url)
                    await harvest(final_url)
                    await soft_navigate(final_url)
                except PlaywrightError as exc:
                    result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
            await context.close()
            await browser.close()
    except PlaywrightError as exc:
        raise BrowserUnavailable(
            "Chromium could not start; run 'playwright install chromium' and retry browser crawl"
        ) from exc

    result.urls = sorted(discovered)
    return result


@dataclass(frozen=True, slots=True)
class XssBrowserVerdict:
    executed: bool
    dialog_message: str | None = None
    final_url: str | None = None
    error: str | None = None


async def verify_reflected_xss(
    probe_url: str,
    *,
    target: str,
    custom_headers: dict[str, str] | None = None,
    navigation_timeout_ms: int = 12_000,
    marker: str = "APOCALYPSE_XSS",
) -> XssBrowserVerdict:
    """Open a reflected XSS candidate URL in Chromium and detect dialog execution.

    Uses a non-destructive alert/prompt canary already present in the probe URL, or injects
    nothing beyond navigating to the provided URL. Callers should put a unique marker into
    an onerror/alert payload before invoking this helper.
    """
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise BrowserUnavailable("browser XSS verification requires the 'browser' extra") from exc

    if not same_origin(probe_url, target):
        return XssBrowserVerdict(False, error="probe URL outside authorized origin")

    headers = {name: value for name, value in (custom_headers or {}).items() if name.lower() != "cookie"}
    cookie_header = next((value for name, value in (custom_headers or {}).items() if name.lower() == "cookie"), "")
    dialog_message: str | None = None

    try:
        async with async_playwright() as playwright:
            browser = await launch_chromium(playwright, headless=True)
            context = await browser.new_context(
                accept_downloads=False,
                extra_http_headers=headers,
                service_workers="block",
            )
            if cookie_header:
                cookies = cookies_from_header(cookie_header, target)
                if cookies:
                    await context.add_cookies(cookies)
            page = await context.new_page()
            page.set_default_timeout(navigation_timeout_ms)

            async def on_dialog(dialog: object) -> None:
                nonlocal dialog_message
                dialog_message = str(getattr(dialog, "message", "") or "")
                await dialog.accept()  # type: ignore[attr-defined]

            page.on("dialog", on_dialog)
            try:
                await page.goto(probe_url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)
                await page.wait_for_timeout(600)
            except PlaywrightError as exc:
                await context.close()
                await browser.close()
                return XssBrowserVerdict(False, error=str(exc))
            final_url = page.url
            await context.close()
            await browser.close()
    except PlaywrightError as exc:
        raise BrowserUnavailable(f"XSS verification failed to start Chromium: {exc}") from exc

    executed = bool(dialog_message and (marker in dialog_message or dialog_message.strip()))
    return XssBrowserVerdict(executed=executed, dialog_message=dialog_message, final_url=final_url)
