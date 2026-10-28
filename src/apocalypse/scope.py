from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def _is_public(value: str) -> bool:
    return ipaddress.ip_address(value).is_global


def is_blocked_ip(value: str) -> bool:
    """True for private, loopback, link-local, multicast, or reserved addresses."""
    try:
        return not _is_public(value)
    except ValueError:
        return True


def resolve_host_ips(host: str, port: int | None = None) -> set[str]:
    host = (host or "").lower().rstrip(".")
    if not host:
        raise ScopeError("hostname is required")
    try:
        ipaddress.ip_address(host)
        return {host}
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS resolution failed: {exc}") from exc
    addresses = {item[4][0] for item in infos}
    if not addresses:
        raise ScopeError("DNS resolution returned no addresses")
    return addresses


def assert_host_allowed(host: str, *, allow_private: bool = False, port: int | None = None) -> set[str]:
    """Resolve host and ensure destinations are acceptable for outbound server requests."""
    addresses = resolve_host_ips(host, port)
    if not allow_private and any(is_blocked_ip(value) for value in addresses):
        raise ScopeError("private, loopback, link-local, or reserved destinations are blocked")
    return addresses


def pin_url_for_request(url: str, *, allow_private: bool = False) -> tuple[str, str, set[str]]:
    """Resolve URL host, reject blocked IPs, and rewrite the URL to a concrete IP.

    Returns (pinned_url, original_host_header_value, resolved_ips). Callers should set the
    Host header (and TLS SNI) to the original hostname to close DNS-rebinding windows.
    """
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        raise ScopeError("only complete http(s) URLs are allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = assert_host_allowed(host, allow_private=allow_private, port=port)
    # Prefer IPv4 for broader httpx compatibility when both exist.
    ip = sorted(addresses, key=lambda item: (":" in item, item))[0]
    if ":" in ip:
        netloc = f"[{ip}]:{port}"
    else:
        netloc = f"{ip}:{port}"
    host_header = host if parsed.port is None else f"{host}:{parsed.port}"
    pinned = urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
    return pinned, host_header, addresses


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
            assert_host_allowed(host, allow_private=False, port=parsed.port or self._port(parsed.scheme, None))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
