from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from .models import Finding, now_iso


SUPPORTED_PROVIDERS = ("github", "webhook", "jira", "servicenow")


def validate_ticket_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"ticket provider must be one of {', '.join(SUPPORTED_PROVIDERS)}")
    if provider == "github":
        repo = str(config.get("repo", "")).strip()
        token_env = str(config.get("token_env", "GITHUB_TOKEN")).strip() or "GITHUB_TOKEN"
        if "/" not in repo:
            raise ValueError("github config requires repo as owner/name")
        return {"repo": repo, "token_env": token_env, "labels": list(config.get("labels") or ["apocalypse"])}
    if provider == "jira":
        base_url = str(config.get("base_url", "")).strip().rstrip("/")
        project = str(config.get("project_key", "")).strip()
        token_env = str(config.get("token_env", "JIRA_TOKEN")).strip() or "JIRA_TOKEN"
        email_env = str(config.get("email_env", "JIRA_EMAIL")).strip() or "JIRA_EMAIL"
        issue_type = str(config.get("issue_type", "Bug")).strip() or "Bug"
        if urlsplit(base_url).scheme not in {"http", "https"} or not project:
            raise ValueError("jira config requires base_url and project_key")
        return {
            "base_url": base_url, "project_key": project, "token_env": token_env,
            "email_env": email_env, "issue_type": issue_type,
        }
    if provider == "servicenow":
        base_url = str(config.get("base_url", "")).strip().rstrip("/")
        token_env = str(config.get("token_env", "SERVICENOW_TOKEN")).strip() or "SERVICENOW_TOKEN"
        table = str(config.get("table", "incident")).strip() or "incident"
        if urlsplit(base_url).scheme not in {"http", "https"}:
            raise ValueError("servicenow config requires base_url")
        return {"base_url": base_url, "token_env": token_env, "table": table}
    url = str(config.get("url", "")).strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("webhook ticket config requires an absolute http(s) url")
    return {"url": url, "token_env": str(config.get("token_env", "")).strip() or None}


def finding_ticket_key(scan_id: str, finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, Finding):
        rule_id, url = finding.rule_id, finding.url
        parameter = str((finding.evidence or {}).get("parameter", ""))
    else:
        rule_id, url = str(finding.get("rule_id", "")), str(finding.get("url", ""))
        evidence = finding.get("evidence") or {}
        parameter = str(evidence.get("parameter", "")) if isinstance(evidence, dict) else ""
    return f"{scan_id}|{rule_id}|{url}|{parameter}"


def _token(token_env: str | None) -> str:
    if not token_env:
        raise ValueError("ticket token environment variable is required")
    value = os.environ.get(token_env)
    if not value:
        raise ValueError(f"ticket token environment variable is unset: {token_env}")
    return value


def _auth_headers(token_env: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(token_env)}"}


def _issue_body(finding: dict[str, Any], scan: dict[str, Any]) -> str:
    return (
        f"Target: {scan.get('target')}\n"
        f"Scan: {scan.get('id')}\n"
        f"Rule: {finding.get('rule_id')}\n"
        f"URL: {finding.get('url')}\n"
        f"Severity: {finding.get('severity')} / {finding.get('confidence')}\n\n"
        f"{finding.get('description', '')}\n\n"
        f"Remediation: {finding.get('remediation', '')}\n"
    )


async def create_external_ticket(
    provider: str, config: dict[str, Any], *, finding: dict[str, Any], scan: dict[str, Any],
) -> dict[str, Any]:
    title = f"[Apocalypse] {finding.get('severity', '').upper()} {finding.get('title', 'Finding')}"
    body = _issue_body(finding, scan)

    if provider == "github":
        owner, repo = str(config["repo"]).split("/", 1)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Apocalypse-Tickets/0.8",
            **_auth_headers(config.get("token_env")),
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/issues",
                headers=headers,
                json={"title": title[:200], "body": body, "labels": config.get("labels") or ["apocalypse"]},
            )
            response.raise_for_status()
            payload = response.json()
        return {
            "external_id": str(payload.get("number")),
            "external_url": str(payload.get("html_url")),
            "status": str(payload.get("state") or "open"),
            "synced_at": now_iso(),
        }

    if provider == "jira":
        email = os.environ.get(str(config.get("email_env") or "JIRA_EMAIL"))
        if not email:
            raise ValueError(f"jira email environment variable is unset: {config.get('email_env')}")
        auth = (email, _token(config.get("token_env")))
        payload = {
            "fields": {
                "project": {"key": config["project_key"]},
                "summary": title[:255],
                "description": body,
                "issuetype": {"name": config.get("issue_type") or "Bug"},
                "labels": ["apocalypse"],
            }
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                f"{config['base_url']}/rest/api/2/issue",
                auth=auth,
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
            created = response.json()
            key = str(created.get("key") or created.get("id"))
        return {
            "external_id": key,
            "external_url": f"{config['base_url']}/browse/{key}",
            "status": "open",
            "synced_at": now_iso(),
        }

    if provider == "servicenow":
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Apocalypse-Tickets/0.8",
            **_auth_headers(config.get("token_env")),
        }
        table = config.get("table") or "incident"
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                f"{config['base_url']}/api/now/table/{table}",
                headers=headers,
                json={
                    "short_description": title[:160],
                    "description": body,
                    "urgency": "2" if finding.get("severity") in {"critical", "high"} else "3",
                    "category": "software",
                    "correlation_id": finding_ticket_key(str(scan.get("id")), finding)[:100],
                },
            )
            response.raise_for_status()
            result = (response.json() or {}).get("result") or {}
            sys_id = str(result.get("sys_id") or result.get("number") or "created")
        return {
            "external_id": sys_id,
            "external_url": f"{config['base_url']}/nav_to.do?uri={table}.do?sys_id={sys_id}",
            "status": str(result.get("state") or "open"),
            "synced_at": now_iso(),
        }

    headers = {"Content-Type": "application/json", "User-Agent": "Apocalypse-Tickets/0.8"}
    headers.update(_auth_headers(config.get("token_env")) if config.get("token_env") else {})
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            config["url"],
            headers=headers,
            json={"event": "ticket.create", "title": title, "body": body, "finding": finding, "scan_id": scan.get("id")},
        )
        response.raise_for_status()
        payload = response.json() if response.content else {}
    return {
        "external_id": str(payload.get("id") or payload.get("external_id") or "created"),
        "external_url": str(payload.get("url") or payload.get("external_url") or config["url"]),
        "status": str(payload.get("status") or "open"),
        "synced_at": now_iso(),
    }


async def sync_external_ticket(provider: str, config: dict[str, Any], ticket: dict[str, Any]) -> dict[str, Any]:
    if provider == "github":
        owner, repo = str(config["repo"]).split("/", 1)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Apocalypse-Tickets/0.8",
            **_auth_headers(config.get("token_env")),
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/issues/{ticket['external_id']}",
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
        return {
            "status": str(payload.get("state") or ticket.get("status") or "open"),
            "external_url": str(payload.get("html_url") or ticket.get("external_url")),
            "synced_at": now_iso(),
            "raw": {"state": payload.get("state"), "closed_at": payload.get("closed_at")},
        }

    if provider == "jira":
        email = os.environ.get(str(config.get("email_env") or "JIRA_EMAIL"))
        if not email:
            raise ValueError(f"jira email environment variable is unset: {config.get('email_env')}")
        auth = (email, _token(config.get("token_env")))
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                f"{config['base_url']}/rest/api/2/issue/{ticket['external_id']}",
                auth=auth,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        status = (((payload.get("fields") or {}).get("status") or {}).get("name") or ticket.get("status") or "open")
        return {
            "status": str(status).lower(),
            "external_url": f"{config['base_url']}/browse/{ticket['external_id']}",
            "synced_at": now_iso(),
            "raw": {"status": status, "updated": (payload.get("fields") or {}).get("updated")},
        }

    if provider == "servicenow":
        table = config.get("table") or "incident"
        headers = {
            "Accept": "application/json",
            "User-Agent": "Apocalypse-Tickets/0.8",
            **_auth_headers(config.get("token_env")),
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(
                f"{config['base_url']}/api/now/table/{table}/{ticket['external_id']}",
                headers=headers,
            )
            response.raise_for_status()
            result = (response.json() or {}).get("result") or {}
        state = str(result.get("state") or ticket.get("status") or "open")
        return {
            "status": state,
            "external_url": str(ticket.get("external_url") or config["base_url"]),
            "synced_at": now_iso(),
            "raw": {"state": state, "number": result.get("number")},
        }

    headers = {"Accept": "application/json", "User-Agent": "Apocalypse-Tickets/0.8"}
    if config.get("token_env"):
        headers.update(_auth_headers(config.get("token_env")))
    url = str(ticket.get("external_url") or config["url"]).rstrip("/") + "/" + str(ticket.get("external_id"))
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        payload = response.json() if response.content else {}
    return {
        "status": str(payload.get("status") or ticket.get("status") or "open"),
        "external_url": str(payload.get("url") or ticket.get("external_url") or config["url"]),
        "synced_at": now_iso(),
        "raw": payload if isinstance(payload, dict) else {},
    }


def dump_config(config: dict[str, Any]) -> str:
    return json.dumps(config, ensure_ascii=False)
