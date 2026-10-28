from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx


def validate_oidc_config(raw: dict[str, Any]) -> dict[str, Any]:
    issuer = str(raw.get("issuer", "")).strip().rstrip("/")
    client_id = str(raw.get("client_id", "")).strip()
    redirect_uri = str(raw.get("redirect_uri", "")).strip()
    client_secret_env = str(raw.get("client_secret_env", "OIDC_CLIENT_SECRET")).strip() or "OIDC_CLIENT_SECRET"
    default_tenant_id = str(raw.get("default_tenant_id") or "default").strip() or "default"
    if not issuer or urlsplit(issuer).scheme not in {"http", "https"}:
        raise ValueError("OIDC issuer must be an absolute http(s) URL")
    if not client_id:
        raise ValueError("OIDC client_id is required")
    if urlsplit(redirect_uri).scheme not in {"http", "https"}:
        raise ValueError("OIDC redirect_uri must be an absolute http(s) URL")
    if not default_tenant_id.replace("-", "").replace("_", "").isalnum():
        raise ValueError("OIDC default_tenant_id must be alphanumeric")
    return {
        "issuer": issuer,
        "client_id": client_id,
        "client_secret_env": client_secret_env,
        "redirect_uri": redirect_uri,
        "scopes": str(raw.get("scopes") or "openid profile email"),
        "default_tenant_id": default_tenant_id,
    }


async def discover_oidc(issuer: str) -> dict[str, Any]:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        payload = response.json()
    if not payload.get("authorization_endpoint") or not payload.get("token_endpoint"):
        raise ValueError("OIDC discovery document missing authorization/token endpoints")
    return payload


def build_authorize_url(discovery: dict[str, Any], config: dict[str, Any], *, state: str, nonce: str) -> str:
    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": config.get("scopes") or "openid profile email",
        "state": state,
        "nonce": nonce,
    }
    base = str(discovery["authorization_endpoint"])
    joiner = "&" if urlsplit(base).query else "?"
    return base + joiner + urlencode(params)


async def exchange_code_for_claims(
    discovery: dict[str, Any],
    config: dict[str, Any],
    *,
    code: str,
    client_secret: str,
) -> dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config["redirect_uri"],
        "client_id": config["client_id"],
        "client_secret": client_secret,
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        token_response = await client.post(discovery["token_endpoint"], data=data)
        token_response.raise_for_status()
        token_payload = token_response.json()
        userinfo_url = discovery.get("userinfo_endpoint")
        headers = {"Authorization": f"Bearer {token_payload.get('access_token', '')}"}
        if userinfo_url and token_payload.get("access_token"):
            info = await client.get(userinfo_url, headers=headers)
            info.raise_for_status()
            claims = info.json()
        else:
            # Fallback: decode unsigned claims are not trusted; require userinfo.
            raise ValueError("OIDC provider did not return a usable userinfo endpoint/access_token")
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip()
    name = str(claims.get("name") or email or claims.get("sub") or "sso-user").strip()
    subject = str(claims.get("sub") or email)
    if not subject:
        raise ValueError("OIDC claims missing sub/email")
    return {"email": email or subject, "name": name[:80], "subject": subject, "claims": claims}


def new_sso_state() -> tuple[str, str]:
    return secrets.token_urlsafe(24), secrets.token_urlsafe(24)


def tenant_slug(name: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name.strip())
    slug = "-".join(part for part in slug.split("-") if part)
    return (slug or "tenant")[:48]


def default_tenant() -> dict[str, Any]:
    return {
        "id": "default",
        "name": "Default",
        "slug": "default",
        "created_at": None,
    }
