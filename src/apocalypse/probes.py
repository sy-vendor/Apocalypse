"""Bounded active-check helpers: LFI, SSTI, SSRF canaries with confirmation chains."""

from __future__ import annotations

import re
from dataclasses import dataclass


PASSWD_FINGERPRINT = re.compile(r"(?m)^root:[^:]*:\d+:\d+:")
WIN_INI_FINGERPRINT = re.compile(r"(?is)\[fonts\]|\[extensions\]|for 16-bit app support")
SSTI_EVAL_HINT = re.compile(r"(?i)(?:jinja|twig|freemarker|velocity|smarty|template syntax)")


@dataclass(frozen=True, slots=True)
class ProbeCanary:
    primary: str
    confirm: str
    kind: str


def looks_path_parameter(name: str) -> bool:
    return bool(re.match(
        r"(?i)^(?:file|path|filepath|filename|template|page|doc|document|include|dir|folder|view|load)$",
        name,
    ))


def looks_url_parameter(name: str) -> bool:
    return bool(re.match(
        r"(?i)^(?:url|uri|src|source|href|link|dest|destination|target|endpoint|callback|webhook|"
        r"fetch|proxy|host|site|feed|image|avatar|redirect|next|return|returnurl|continue)$",
        name,
    ))


def looks_template_parameter(name: str) -> bool:
    return bool(re.match(
        r"(?i)^(?:template|tpl|name|title|message|text|body|content|q|query|search|expr|expression)$",
        name,
    ))


def lfi_canaries() -> tuple[ProbeCanary, ...]:
    return (
        ProbeCanary("../../../../../../etc/passwd", "../../../../../../etc/passwd%00", "unix-passwd"),
        ProbeCanary("..\\..\\..\\..\\windows\\win.ini", "....//....//windows/win.ini", "win-ini"),
        ProbeCanary("/etc/passwd", "file:///etc/passwd", "unix-abs"),
    )


def detect_lfi(body: str) -> str | None:
    if PASSWD_FINGERPRINT.search(body or ""):
        return "passwd-root"
    if WIN_INI_FINGERPRINT.search(body or ""):
        return "win-ini"
    return None


def ssti_canaries() -> tuple[ProbeCanary, ...]:
    # Arithmetic that should evaluate to a distinctive number if templates render server-side.
    return (
        ProbeCanary("{{7*7}}", "{{7*'7'}}", "jinja-like"),
        ProbeCanary("${7*7}", "${7*'7'}", "dollar-expr"),
        ProbeCanary("<%= 7*7 %>", "<%= 7*'7' %>", "erb-like"),
    )


def score_ssti(primary_body: str, confirm_body: str, *, primary: str, confirm: str) -> dict[str, object]:
    """Require 49 in primary response and absence (or different) for non-evaluating confirm."""
    has_forty_nine = "49" in (primary_body or "")
    confirm_has = "49" in (confirm_body or "")
    # Confirm payload {{7*'7'}} often yields 7777777 or literal; treat shared 49 as weak.
    chain_verified = has_forty_nine and not confirm_has
    error_hint = SSTI_EVAL_HINT.search(primary_body or "")
    return {
        "primary_payload": primary,
        "confirm_payload": confirm,
        "saw_49": has_forty_nine,
        "confirm_saw_49": confirm_has,
        "template_error_hint": error_hint.group(0)[:80] if error_hint else None,
        "chain_verified": chain_verified,
    }


def ssrf_canaries(oast_url: str, marker: str) -> tuple[str, str]:
    """Primary OAST URL plus a same-token confirm path for double-hit confidence."""
    primary = oast_url
    joiner = "&" if "?" in oast_url else "?"
    confirm = f"{oast_url}{joiner}confirm={marker}"
    return primary, confirm
