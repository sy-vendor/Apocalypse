from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


def _matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def _unsafe_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not ip.is_global


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    allow_hosts: tuple[str, ...]
    deny_hosts: tuple[str, ...] = ()
    allow_http: bool = False

    def validate_url(self, url: str, *, resolve_dns: bool = True) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in ({"https", "http"} if self.allow_http else {"https"}):
            raise ScopeError("URL scheme is not permitted")
        if parsed.username or parsed.password:
            raise ScopeError("Credentials in URL are not permitted")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host == "localhost":
            raise ScopeError("A public hostname is required")
        if any(_matches(host, p) for p in self.deny_hosts):
            raise ScopeError(f"Host is explicitly denied: {host}")
        if not any(_matches(host, p) for p in self.allow_hosts):
            raise ScopeError(f"Host is outside the configured allowlist: {host}")
        try:
            if _unsafe_ip(host):
                raise ScopeError("Non-public IP targets are not permitted")
        except ValueError:
            if resolve_dns:
                try:
                    addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443)}
                except socket.gaierror as exc:
                    raise ScopeError(f"DNS resolution failed for {host}: {exc}") from exc
                if not addresses or any(_unsafe_ip(ip) for ip in addresses):
                    raise ScopeError("Hostname resolves to a non-public address")
        return host

