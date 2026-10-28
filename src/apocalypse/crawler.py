from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


SKIP_EXTENSIONS = {
    ".7z", ".avi", ".css", ".dmg", ".doc", ".docx", ".gif", ".gz", ".ico", ".jpeg", ".jpg",
    ".mov", ".mp3", ".mp4", ".pdf", ".png", ".rar", ".svg", ".tar", ".webp", ".woff", ".woff2", ".xls", ".xlsx", ".zip",
}
STATEFUL_WORDS = {"delete", "destroy", "logout", "remove", "signout", "unsubscribe"}
JS_URL = re.compile(r'''["']((?:https?://|/)[^"'<>\s]{1,400})["']''')


@dataclass(slots=True)
class FormInfo:
    source_url: str
    action: str
    method: str
    enctype: str = "application/x-www-form-urlencoded"
    inputs: list[dict[str, str]] = field(default_factory=list)


class DocumentParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.mixed_content: set[str] = set()
        self.forms: list[FormInfo] = []
        self._form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        for name in ("href", "src", "action"):
            value = values.get(name)
            if value:
                self.links.add(value)
                if self.base_url.startswith("https://") and value.startswith("http://"):
                    self.mixed_content.add(value)
        if tag.lower() == "form":
            self._form = FormInfo(
                source_url=self.base_url,
                action=urljoin(self.base_url, values.get("action") or self.base_url),
                method=(values.get("method") or "GET").upper(),
                enctype=(values.get("enctype") or "application/x-www-form-urlencoded").lower(),
            )
            self.forms.append(self._form)
        elif tag.lower() == "input" and self._form is not None:
            self._form.inputs.append({
                "name": values.get("name", ""),
                "type": values.get("type", "text").lower(),
                "autocomplete": values.get("autocomplete", ""),
                "value": values.get("value", ""),
            })
        elif tag.lower() == "textarea" and self._form is not None:
            self._form.inputs.append({"name": values.get("name", ""), "type": "textarea", "value": ""})
        elif tag.lower() == "select" and self._form is not None:
            self._form.inputs.append({"name": values.get("name", ""), "type": "select", "value": ""})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


def normalize_candidate(base_url: str, value: str) -> str | None:
    value = value.strip().rstrip("\\")
    if not value or value.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
        return None
    absolute = urljoin(base_url, value)
    parsed, base = urlsplit(absolute), urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != base.hostname:
        return None
    path = parsed.path or "/"
    if any(part.lower() in STATEFUL_WORDS for part in path.split("/")):
        return None
    if any(path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def parse_document(url: str, content_type: str, text: str) -> tuple[list[str], list[FormInfo], list[str]]:
    parser = DocumentParser(url)
    values: set[str] = set()
    if "html" in content_type.lower():
        parser.feed(text)
        values.update(parser.links)
    if any(kind in content_type.lower() for kind in ("html", "javascript", "json", "text")):
        values.update(match.group(1) for match in JS_URL.finditer(text))
    normalized = {normalize_candidate(url, value) for value in values}
    return sorted(item for item in normalized if item), parser.forms, sorted(parser.mixed_content)

