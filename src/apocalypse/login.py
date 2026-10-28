from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .browser import BrowserUnavailable, launch_chromium, same_origin


ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
ALLOWED_ACTIONS = {"goto", "fill", "click", "press", "wait", "wait_for_url", "wait_for_selector"}


@dataclass(slots=True)
class LoginStep:
    action: str
    url: str | None = None
    selector: str | None = None
    value: str | None = None
    key: str | None = None
    contains: str | None = None
    timeout_ms: int = 12_000
    secret: bool = False


@dataclass(slots=True)
class LoginFlow:
    start_url: str
    steps: list[LoginStep] = field(default_factory=list)
    success_url_contains: str | None = None

    def public_summary(self) -> dict[str, Any]:
        return {
            "start_url": self.start_url,
            "success_url_contains": self.success_url_contains,
            "steps": [
                {
                    "action": step.action,
                    "url": step.url,
                    "selector": step.selector,
                    "contains": step.contains,
                    "secret": step.secret,
                    "has_value": bool(step.value),
                }
                for step in self.steps
            ],
        }


@dataclass(slots=True)
class LoginResult:
    cookie_header: str
    final_url: str
    ok: bool
    errors: list[str] = field(default_factory=list)


def _expand_value(raw: str | None, *, secret_overrides: dict[str, str] | None = None) -> str:
    if raw is None:
        return ""
    overrides = secret_overrides or {}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in overrides:
            return overrides[name]
        value = os.environ.get(name)
        if value is None:
            raise ValueError(
                f"login flow references unset environment variable: {name} "
                "(provide it via the scan password field or export it before serve)"
            )
        return value

    return ENV_REF.sub(replace, raw)


def normalize_login_secrets(
    raw: object | None,
    *,
    login_password: str | None = None,
) -> dict[str, str]:
    """Ephemeral secret map for ${ENV} expansion. Never persist the return value."""
    secrets: dict[str, str] = {}
    if isinstance(raw, dict):
        if len(raw) > 20:
            raise ValueError("login_secrets allows at most 20 entries")
        for key, value in raw.items():
            name = str(key).strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError(f"invalid login secret name: {name}")
            text = str(value)
            if len(text) > 4096:
                raise ValueError(f"login secret {name} is too long")
            secrets[name] = text
    elif raw not in (None, ""):
        raise ValueError("login_secrets must be an object")
    password = (login_password or "").strip()
    if password:
        if len(password) > 4096:
            raise ValueError("login_password is too long")
        secrets.setdefault("APOCALYPSE_PASSWORD", password)
    return secrets


def parse_login_flow_document(
    document: dict[str, Any],
    *,
    expand_secrets: bool = True,
    secret_overrides: dict[str, str] | None = None,
) -> LoginFlow:
    if not isinstance(document, dict):
        raise ValueError("login flow must be a JSON object")
    start_url = str(document.get("start_url") or "").strip()
    if not start_url:
        raise ValueError("login flow requires start_url")
    parsed = urlsplit(start_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("login start_url must be an absolute http(s) URL")
    raw_steps = document.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("login flow requires a non-empty steps array")
    if len(raw_steps) > 40:
        raise ValueError("login flow allows at most 40 steps")
    steps: list[LoginStep] = []
    for index, item in enumerate(raw_steps):
        if not isinstance(item, dict):
            raise ValueError(f"login step {index} must be an object")
        action = str(item.get("action", "")).strip()
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"unsupported login action: {action}")
        timeout_ms = int(item.get("timeout_ms", 12_000))
        if not 100 <= timeout_ms <= 60_000:
            raise ValueError("login step timeout_ms must be between 100 and 60000")
        raw_value = str(item["value"]) if "value" in item and item["value"] is not None else None
        value = (
            _expand_value(raw_value, secret_overrides=secret_overrides)
            if expand_secrets
            else (raw_value or "")
        )
        steps.append(LoginStep(
            action=action,
            url=str(item["url"]).strip() if item.get("url") else None,
            selector=str(item["selector"]).strip() if item.get("selector") else None,
            value=value,
            key=str(item["key"]).strip() if item.get("key") else None,
            contains=str(item["contains"]) if item.get("contains") is not None else None,
            timeout_ms=timeout_ms,
            secret=bool(item.get("secret")),
        ))
    success = document.get("success_url_contains")
    return LoginFlow(
        start_url=start_url,
        steps=steps,
        success_url_contains=str(success) if success else None,
    )


def load_login_flow(path: Path, *, secret_overrides: dict[str, str] | None = None) -> LoginFlow:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("login flow must be a JSON object")
    return parse_login_flow_document(document, secret_overrides=secret_overrides)


def _cookie_header_from_context_cookies(cookies: list[dict[str, Any]], target: str) -> str:
    host = (urlsplit(target).hostname or "").lower()
    pairs: list[str] = []
    for item in cookies:
        domain = str(item.get("domain", "")).lstrip(".").lower()
        if domain and host != domain and not host.endswith("." + domain):
            continue
        name, value = str(item.get("name", "")), str(item.get("value", ""))
        if name and "\n" not in name and "\n" not in value:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


async def replay_login_flow(flow: LoginFlow, *, target: str, navigation_timeout_ms: int = 12_000) -> LoginResult:
    """Replay a recorded login in Chromium and return session cookies for subsequent scanning."""
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise BrowserUnavailable(
            "login replay requires the 'browser' extra: pip install -e '.[browser]' "
            "(uses local Google Chrome when available)"
        ) from exc

    if not same_origin(flow.start_url, target):
        raise ValueError("login start_url must stay inside the authorized target origin")

    errors: list[str] = []
    try:
        async with async_playwright() as playwright:
            browser = await launch_chromium(playwright, headless=True)
            context = await browser.new_context(accept_downloads=False, service_workers="block")
            page = await context.new_page()
            page.set_default_timeout(navigation_timeout_ms)
            await page.goto(flow.start_url, wait_until="domcontentloaded", timeout=navigation_timeout_ms)

            for index, step in enumerate(flow.steps):
                try:
                    if step.action == "goto":
                        if not step.url or not same_origin(step.url, target):
                            raise ValueError("goto URL missing or outside authorized origin")
                        await page.goto(step.url, wait_until="domcontentloaded", timeout=step.timeout_ms)
                    elif step.action == "fill":
                        if not step.selector:
                            raise ValueError("fill requires selector")
                        locator = page.locator(step.selector).first
                        input_type = (
                            await locator.get_attribute("type", timeout=step.timeout_ms) or ""
                        ).lower()
                        # Legacy recordings sometimes stored checkbox toggles as fill.
                        if input_type in {"checkbox", "radio"}:
                            await locator.click(timeout=step.timeout_ms)
                        else:
                            await locator.fill(step.value or "", timeout=step.timeout_ms)
                    elif step.action == "click":
                        if not step.selector:
                            raise ValueError("click requires selector")
                        await page.click(step.selector, timeout=step.timeout_ms)
                    elif step.action == "press":
                        if not step.selector or not step.key:
                            raise ValueError("press requires selector and key")
                        await page.press(step.selector, step.key, timeout=step.timeout_ms)
                    elif step.action == "wait":
                        await page.wait_for_timeout(min(step.timeout_ms, 5_000))
                    elif step.action == "wait_for_url":
                        needle = step.contains or ""
                        await page.wait_for_function(
                            "(value) => String(location.href).includes(value)",
                            arg=needle,
                            timeout=step.timeout_ms,
                        )
                    elif step.action == "wait_for_selector":
                        if not step.selector:
                            raise ValueError("wait_for_selector requires selector")
                        await page.wait_for_selector(step.selector, timeout=step.timeout_ms)
                    if not same_origin(page.url, target):
                        raise ValueError(f"login navigated outside authorized origin: {urlsplit(page.url).hostname}")
                except (PlaywrightError, ValueError) as exc:
                    errors.append(f"step {index} {step.action}: {type(exc).__name__}: {exc}")
                    break

            final_url = page.url
            ok = not errors
            if flow.success_url_contains and flow.success_url_contains not in final_url:
                ok = False
                errors.append(f"success_url_contains not matched: {flow.success_url_contains}")
            cookie_header = _cookie_header_from_context_cookies(await context.cookies(), target)
            await context.close()
            await browser.close()
            return LoginResult(cookie_header=cookie_header, final_url=final_url, ok=ok, errors=errors)
    except PlaywrightError as exc:
        raise BrowserUnavailable(
            "Chromium could not start for login replay; run 'playwright install chromium'"
        ) from exc


def example_login_flow() -> dict[str, Any]:
    return {
        "start_url": "https://app.example.com/login",
        "success_url_contains": "/dashboard",
        "steps": [
            {"action": "goto", "url": "https://app.example.com/login"},
            {"action": "fill", "selector": "input[name=email]", "value": "tester@example.com"},
            {"action": "fill", "selector": "input[name=password]", "value": "${APOCALYPSE_PASSWORD}", "secret": True},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "wait_for_url", "contains": "/dashboard", "timeout_ms": 15000},
        ],
    }


RECORDER_INIT_SCRIPT = """
(() => {
  if (window.__apocalypseRecorder) return;
  window.__apocalypseRecorder = true;
  const cssPath = (el) => {
    if (!el || el.nodeType !== 1) return '';
    if (el.id) return `#${CSS.escape(el.id)}`;
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && parts.length < 5) {
      let part = node.nodeName.toLowerCase();
      if (node.name) part += `[name="${CSS.escape(node.name)}"]`;
      else if (node.getAttribute('type')) part += `[type="${CSS.escape(node.getAttribute('type'))}"]`;
      else {
        const parent = node.parentElement;
        if (parent) {
          const siblings = [...parent.children].filter((x) => x.nodeName === node.nodeName);
          if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(node) + 1})`;
        }
      }
      parts.unshift(part);
      if (node.id || (node.name && ['INPUT','SELECT','TEXTAREA','BUTTON'].includes(node.nodeName))) break;
      node = node.parentElement;
    }
    return parts.join(' > ');
  };
  const emit = (payload) => {
    try { window.apocalypseRecord && window.apocalypseRecord(payload); } catch (_) {}
  };
  document.addEventListener('click', (event) => {
    const el = event.target;
    if (!el || el.closest('#apocalypse-recorder-bar')) return;
    emit({ action: 'click', selector: cssPath(el), url: location.href });
  }, true);
  document.addEventListener('change', (event) => {
    const el = event.target;
    if (!el || !['INPUT','TEXTAREA','SELECT'].includes(el.nodeName)) return;
    const type = (el.type || '').toLowerCase();
    // Checkboxes/radios are toggles — never record as fill (Playwright cannot fill them).
    if (type === 'checkbox' || type === 'radio') {
      emit({ action: 'click', selector: cssPath(el), url: location.href });
      return;
    }
    const secret = type === 'password' || /pass|secret|token/i.test(el.name || el.id || '');
    emit({
      action: 'fill',
      selector: cssPath(el),
      value: secret ? '${APOCALYPSE_PASSWORD}' : String(el.value || '').slice(0, 200),
      secret,
      url: location.href,
    });
  }, true);
  const bar = document.createElement('div');
  bar.id = 'apocalypse-recorder-bar';
  bar.innerHTML = '<strong>Apocalypse recording</strong><span>Interact with the page, then click Done</span><button type="button" id="apocalypse-done">Done</button>';
  bar.style.cssText = 'position:fixed;z-index:2147483647;left:12px;right:12px;bottom:12px;display:flex;gap:12px;align-items:center;justify-content:space-between;padding:12px 16px;border-radius:12px;background:#0f172a;color:#e2e8f0;font:13px/1.4 system-ui;box-shadow:0 10px 40px #0008';
  const mount = () => {
    if (document.getElementById('apocalypse-recorder-bar')) return;
    document.documentElement.appendChild(bar);
    document.getElementById('apocalypse-done').onclick = () => emit({ action: 'done', url: location.href });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
"""


def _redact_recorded_steps(raw_steps: list[dict[str, Any]], start_url: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = [{"action": "goto", "url": start_url}]
    last_url = start_url
    for item in raw_steps:
        action = item.get("action")
        if action == "done":
            continue
        url = str(item.get("url") or last_url)
        if url != last_url:
            steps.append({"action": "goto", "url": url})
            last_url = url
        if action == "fill":
            selector = str(item.get("selector") or "")
            # Defensive: checkbox/radio selectors must replay as click.
            if selector and ("type=\"checkbox\"" in selector or "type=\"radio\"" in selector
                             or selector.endswith("[type=checkbox]") or selector.endswith("[type=radio]")):
                steps.append({"action": "click", "selector": selector})
            else:
                steps.append({
                    "action": "fill",
                    "selector": item.get("selector"),
                    "value": item.get("value") or "",
                    "secret": bool(item.get("secret")),
                })
        elif action == "click":
            steps.append({"action": "click", "selector": item.get("selector")})
    if last_url != start_url:
        path = urlsplit(last_url).path or "/"
        success = path if path != "/" else last_url
    else:
        success = None
    # Drop empty selectors and cap length.
    cleaned = [step for step in steps if step.get("action") == "goto" or step.get("selector")]
    return {
        "start_url": start_url,
        "success_url_contains": success,
        "steps": cleaned[:40],
    }


async def record_login_interactively(
    start_url: str,
    *,
    timeout_seconds: int = 300,
    headed: bool = True,
) -> dict[str, Any]:
    """Launch Chromium and record click/fill interactions into a login-flow JSON document."""
    try:
        from playwright.async_api import Error as PlaywrightError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise BrowserUnavailable(
            "interactive login recording requires the 'browser' extra: pip install -e '.[browser]'"
        ) from exc

    parsed = urlsplit(start_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("start_url must be an absolute http(s) URL")
    if not 30 <= timeout_seconds <= 1800:
        raise ValueError("timeout_seconds must be between 30 and 1800")

    events: list[dict[str, Any]] = []
    done = False

    try:
        async with async_playwright() as playwright:
            browser = await launch_chromium(playwright, headless=not headed)
            context = await browser.new_context(accept_downloads=False, service_workers="block")
            page = await context.new_page()

            def on_record(source: object, payload: dict[str, Any]) -> None:  # noqa: ARG001
                nonlocal done
                if not isinstance(payload, dict):
                    return
                action = payload.get("action")
                if action == "done":
                    done = True
                    return
                if action in {"click", "fill"}:
                    events.append(payload)

            await page.expose_binding("apocalypseRecord", on_record)
            await context.add_init_script(RECORDER_INIT_SCRIPT)
            await page.goto(start_url, wait_until="domcontentloaded")
            # Re-inject if the first document was already loaded before init script on some navigations.
            await page.evaluate(RECORDER_INIT_SCRIPT)

            import asyncio
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout_seconds
            while not done and loop.time() < deadline:
                await page.wait_for_timeout(250)
                if not same_origin(page.url, start_url):
                    # Keep recording same-origin only; stop if user leaves the authorized host.
                    if urlsplit(page.url).hostname != parsed.hostname:
                        break

            final_url = page.url
            await context.close()
            await browser.close()
    except PlaywrightError as exc:
        raise BrowserUnavailable(f"interactive recorder failed: {exc}") from exc

    document = _redact_recorded_steps(events, start_url)
    if final_url and document.get("success_url_contains") is None:
        document["success_url_contains"] = urlsplit(final_url).path or "/"
    parse_login_flow_document(document, expand_secrets=False)
    return document

