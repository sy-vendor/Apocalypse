from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def _is_public(value: str) -> bool:
    return ipaddress.ip_address(value).is_global


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    target: str
    allow_private: bool = False
    exact_origin: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("target must be a complete http(s) URL")
        if parsed.username or parsed.password:
            raise ScopeError("credentials in target URL are not permitted")

    @property
    def host(self) -> str:
        return (urlsplit(self.target).hostname or "").lower().rstrip(".")

    @staticmethod
    def _port(scheme: str, port: int | None) -> int:
        return port or (443 if scheme == "https" else 80)

    def validate(self, url: str, *, resolve_dns: bool = True) -> str:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host:
            raise ScopeError("only complete http(s) URLs are allowed")
        if parsed.username or parsed.password:
            raise ScopeError("credentials in URLs are not permitted")
        if host != self.host:
            raise ScopeError(f"cross-host request blocked: {host}")
        target = urlsplit(self.target)
        if self.exact_origin and (
            parsed.scheme != target.scheme or self._port(parsed.scheme, parsed.port) != self._port(target.scheme, target.port)
        ):
            raise ScopeError("cross-origin request blocked while custom headers are active")
        if resolve_dns and not self.allow_private:
            try:
                ipaddress.ip_address(host)
                addresses = {host}
            except ValueError:
                try:
                    addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443)}
                except socket.gaierror as exc:
                    raise ScopeError(f"DNS resolution failed: {exc}") from exc
            if not addresses or any(not _is_public(value) for value in addresses):
                raise ScopeError("private, loopback, link-local, or reserved destinations are blocked")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))

