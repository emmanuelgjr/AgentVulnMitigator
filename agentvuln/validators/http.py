"""SSRF guard for HTTP tool calls."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def validate_http_url(url: str, *, resolve_dns: bool = True) -> str | None:
    """Return None if `url` is safe, or a reason string if it should be blocked.

    Blocks: non-http(s) schemes, RFC1918 / loopback / link-local / metadata
    hosts, and (when DNS resolution is allowed) hostnames that resolve to
    blocked IPs.
    """
    if not isinstance(url, str) or not url.strip():
        return "empty url"

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return f"scheme {parsed.scheme!r} is not allowed"

    host = (parsed.hostname or "").lower()
    if not host:
        return "url has no host"

    if host in _BLOCKED_HOSTNAMES:
        return f"hostname {host!r} is blocked (cloud metadata)"

    if _is_blocked_ip(host):
        return f"host {host!r} is in a blocked IP range"

    if resolve_dns:
        try:
            for family, _stype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                if _is_blocked_ip(ip):
                    return f"hostname {host!r} resolves to blocked IP {ip!r}"
                if family == socket.AF_INET6 and ip == "::1":
                    return f"hostname {host!r} resolves to loopback"
        except socket.gaierror:
            return f"hostname {host!r} could not be resolved"

    return None
