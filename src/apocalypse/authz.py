"""Dual-session authorization differential checks (IDOR / BOLA heuristics)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


ID_PARAM = re.compile(r"(?i)^(?:id|user_id|userid|account_id|order_id|org_id|tenant_id|uid|uuid)$")
ID_PATH = re.compile(r"(?i)/(?:users?|accounts?|orders?|orgs?|tenants?|profiles?|customers?)/([^/?#]+)")


@dataclass(frozen=True, slots=True)
class AuthzCandidate:
    url: str
    reason: str


def looks_object_url(url: str) -> AuthzCandidate | None:
    parsed = urlsplit(url)
    path_match = ID_PATH.search(parsed.path or "")
    if path_match:
        return AuthzCandidate(url, f"path-object:{path_match.group(1)[:40]}")
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if ID_PARAM.match(name) and value:
            return AuthzCandidate(url, f"query:{name}")
    return None


def select_authz_candidates(urls: list[str], *, limit: int = 12) -> list[AuthzCandidate]:
    selected: list[AuthzCandidate] = []
    seen: set[str] = set()
    for url in urls:
        candidate = looks_object_url(url)
        if not candidate or candidate.url in seen:
            continue
        seen.add(candidate.url)
        selected.append(candidate)
        if len(selected) >= limit:
            break
    return selected


def body_digest(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def score_idor(
    primary_status: int,
    primary_body: str,
    secondary_status: int,
    secondary_body: str,
) -> dict[str, object]:
    """Both sessions receive the object with highly similar bodies → likely BOLA/IDOR."""
    primary_ok = 200 <= primary_status < 300
    secondary_ok = 200 <= secondary_status < 300
    if not primary_ok or not secondary_ok:
        return {
            "differential": False,
            "chain_verified": False,
            "reason": "access-denied-or-error",
            "primary_status": primary_status,
            "secondary_status": secondary_status,
        }
    p_digest = body_digest(primary_body)
    s_digest = body_digest(secondary_body)
    same = p_digest == s_digest
    # Allow tiny wrapper differences (whitespace / timestamps) via length proximity + shared digest prefix.
    length_close = abs(len(primary_body or "") - len(secondary_body or "")) <= max(24, int(0.05 * max(len(primary_body or ""), 1)))
    similar = same or (length_close and p_digest[:8] == s_digest[:8] and len(primary_body or "") >= 40)
    return {
        "differential": similar,
        "chain_verified": similar,
        "reason": "shared-object-across-sessions" if similar else "distinct-responses",
        "primary_status": primary_status,
        "secondary_status": secondary_status,
        "primary_digest": p_digest,
        "secondary_digest": s_digest,
    }
