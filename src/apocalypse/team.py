from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any


ROLES = ("admin", "analyst", "viewer")
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass(frozen=True, slots=True)
class AuthContext:
    user_id: str
    name: str
    role: str


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_token() -> str:
    return secrets.token_urlsafe(32)


def create_user_record(
    name: str, role: str, *, tenant_id: str = "default", sso_subject: str | None = None,
) -> tuple[dict[str, Any], str]:
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if not name.strip() or len(name) > 80:
        raise ValueError("user name must be 1-80 characters")
    token = issue_token()
    return {
        "id": secrets.token_hex(6),
        "name": name.strip(),
        "role": role,
        "token_hash": hash_token(token),
        "tenant_id": tenant_id or "default",
        "sso_subject": sso_subject,
    }, token


def role_allows(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK.get(minimum, 99)


def constant_time_hash_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
