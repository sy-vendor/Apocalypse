from __future__ import annotations

import re
from dataclasses import dataclass


CONTEXT_SEVERITY = {
    "javascript": ("high", "high"),
    "event_handler": ("high", "high"),
    "attribute_unquoted": ("high", "high"),
    "attribute_double": ("medium", "high"),
    "attribute_single": ("medium", "high"),
    "html_text": ("medium", "medium"),
    "css": ("low", "medium"),
    "html_comment": ("info", "medium"),
    "unknown": ("medium", "low"),
}


@dataclass(frozen=True, slots=True)
class ReflectionContext:
    kind: str
    severity: str
    confidence: str


def _inside_block(prefix: str, open_tag: str, close_tag: str) -> bool:
    opens = len(re.findall(open_tag, prefix, flags=re.I))
    closes = len(re.findall(close_tag, prefix, flags=re.I))
    return opens > closes


def _attribute_quote(prefix: str) -> str | None:
    """Return quote style if the marker sits inside an open HTML tag attribute value."""
    last_lt = prefix.rfind("<")
    last_gt = prefix.rfind(">")
    if last_lt == -1 or last_lt < last_gt:
        return None
    tag = prefix[last_lt:]
    if re.search(r"(?i)\son[a-z]+\s*=\s*['\"]?[^'\">]*$", tag):
        return "event"
    # Count quotes after the last '=' inside the open tag.
    eq = tag.rfind("=")
    if eq == -1:
        return None
    after = tag[eq + 1 :].lstrip()
    if not after:
        return "unquoted"
    if after[0] == '"':
        return "double" if after.count('"') == 1 else None
    if after[0] == "'":
        return "single" if after.count("'") == 1 else None
    if re.match(r"[^\s<>'\"=/]+$", after):
        return "unquoted"
    return None


def classify_reflection(body: str, marker: str) -> ReflectionContext:
    """Classify where an unencoded marker appears. No script execution is performed."""
    if not marker or marker not in body:
        return ReflectionContext("unknown", *CONTEXT_SEVERITY["unknown"])

    kinds: set[str] = set()
    for match in re.finditer(re.escape(marker), body):
        prefix = body[max(0, match.start() - 400) : match.start()]
        if _inside_block(prefix, r"<script\b[^>]*>", r"</script\s*>"):
            kinds.add("javascript")
            continue
        if _inside_block(prefix, r"<style\b[^>]*>", r"</style\s*>"):
            kinds.add("css")
            continue
        if "<!--" in prefix and prefix.rfind("<!--") > prefix.rfind("-->"):
            kinds.add("html_comment")
            continue
        quote = _attribute_quote(prefix)
        if quote == "event":
            kinds.add("event_handler")
        elif quote == "unquoted":
            kinds.add("attribute_unquoted")
        elif quote == "double":
            kinds.add("attribute_double")
        elif quote == "single":
            kinds.add("attribute_single")
        else:
            kinds.add("html_text")

    if not kinds:
        return ReflectionContext("unknown", *CONTEXT_SEVERITY["unknown"])

    order = (
        "javascript", "event_handler", "attribute_unquoted", "attribute_double",
        "attribute_single", "html_text", "css", "html_comment", "unknown",
    )
    kind = next(item for item in order if item in kinds)
    severity, confidence = CONTEXT_SEVERITY[kind]
    return ReflectionContext(kind, severity, confidence)
