"""Dual-session authorization differential checks (IDOR / BOLA heuristics)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ID_PARAM = re.compile(
    r"(?i)^(?:id|user_id|userid|account_id|order_id|org_id|tenant_id|uid|uuid|item_id|object_id|record_id|pk)$"
)
# Named resource collections (legacy high-signal paths).
ID_PATH = re.compile(
    r"(?i)/(?:users?|accounts?|orders?|orgs?|tenants?|profiles?|customers?|items?|objects?|records?)/([^/?#]+)"
)
OBJECT_COLLECTION_PATH = re.compile(
    r"(?i)/(?:users?|accounts?|orders?|orgs?|tenants?|profiles?|customers?|items?|objects?|records?)(?:/|$)"
)
# Broader hunting: /api/v1/.../123 or trailing UUID / numeric segment.
API_NUMERIC_PATH = re.compile(r"(?i)/(?:api/)?(?:v\d+/)?(?:[\w.-]+/)*(\d{1,12})(?:/|$|\?)")
UUID_PATH = re.compile(
    r"(?i)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)"
)
@dataclass(frozen=True, slots=True)
class AuthzCandidate:
    url: str
    reason: str


@dataclass(frozen=True, slots=True)
class ObjectMutation:
    original_url: str
    mutated_url: str
    original_value: str
    mutated_value: str
    reason: str


def looks_object_url(url: str) -> AuthzCandidate | None:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    path_match = ID_PATH.search(path)
    if path_match:
        return AuthzCandidate(url, f"path-object:{path_match.group(1)[:40]}")
    uuid_match = UUID_PATH.search(path)
    if uuid_match:
        return AuthzCandidate(url, f"path-uuid:{uuid_match.group(1)[:40]}")
    api_match = API_NUMERIC_PATH.search(path)
    if api_match:
        return AuthzCandidate(url, f"path-id:{api_match.group(1)[:40]}")
    # Query IDs only on collection / API-ish paths — avoid public search ?id= diagnostics.
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in query_pairs:
        if not value or not ID_PARAM.match(name):
            continue
        if (
            OBJECT_COLLECTION_PATH.search(path)
            or path.startswith("/api")
            or "/v1/" in path
            or "/v2/" in path
        ):
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
    length_close = abs(len(primary_body or "") - len(secondary_body or "")) <= max(
        24, int(0.05 * max(len(primary_body or ""), 1)),
    )
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


def score_unauth_access(
    auth_status: int,
    auth_body: str,
    anon_status: int,
    anon_body: str,
) -> dict[str, object]:
    """Authenticated object still readable without credentials → broken access control."""
    score = score_idor(auth_status, auth_body, anon_status, anon_body)
    if score["differential"]:
        score["reason"] = "shared-object-without-auth"
    return {
        "differential": score["differential"],
        "chain_verified": score["chain_verified"],
        "reason": score["reason"],
        "auth_status": auth_status,
        "anon_status": anon_status,
        "auth_digest": score.get("primary_digest"),
        "anon_digest": score.get("secondary_digest"),
    }


def _mutate_numeric(value: str) -> list[str]:
    if not value.isdigit():
        return []
    number = int(value)
    variants = []
    for candidate in (number + 1, number - 1, number + 2):
        if candidate <= 0:
            continue
        text = str(candidate)
        if len(value) > 1 and value.startswith("0"):
            text = text.zfill(len(value))
        if text != value:
            variants.append(text)
    return variants[:2]


def _mutate_uuid(value: str) -> list[str]:
    if not re.fullmatch(
        r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value,
    ):
        return []
    # Flip the last hex nibble to keep format while changing identity.
    last = value[-1]
    replacement = "1" if last.lower() != "1" else "2"
    return [value[:-1] + replacement]


def mutate_object_urls(urls: list[str], *, limit: int = 12) -> list[ObjectMutation]:
    """Produce neighboring object URLs by mutating numeric/UUID path or query identifiers."""
    mutations: list[ObjectMutation] = []
    seen: set[str] = set()

    def push(original: str, mutated: str, original_value: str, mutated_value: str, reason: str) -> None:
        if mutated == original or mutated in seen:
            return
        seen.add(mutated)
        mutations.append(ObjectMutation(original, mutated, original_value, mutated_value, reason))

    for url in urls:
        if len(mutations) >= limit:
            break
        parsed = urlsplit(url)
        path = parsed.path or "/"
        for match in list(ID_PATH.finditer(path)) + list(UUID_PATH.finditer(path)) + list(API_NUMERIC_PATH.finditer(path)):
            original_value = match.group(1)
            for mutated_value in _mutate_numeric(original_value) + _mutate_uuid(original_value):
                mutated_path = path[: match.start(1)] + mutated_value + path[match.end(1) :]
                mutated = urlunsplit((parsed.scheme, parsed.netloc, mutated_path, parsed.query, ""))
                push(url, mutated, original_value, mutated_value, f"path:{original_value}->{mutated_value}")
                if len(mutations) >= limit:
                    return mutations
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for index, (name, value) in enumerate(pairs):
            if not ID_PARAM.match(name) or not value:
                continue
            for mutated_value in _mutate_numeric(value) + _mutate_uuid(value):
                new_pairs = list(pairs)
                new_pairs[index] = (name, mutated_value)
                mutated = urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, urlencode(new_pairs), ""),
                )
                push(url, mutated, value, mutated_value, f"query:{name}:{value}->{mutated_value}")
                if len(mutations) >= limit:
                    return mutations
    return mutations
