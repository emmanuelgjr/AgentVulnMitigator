"""SSRF guard for HTTP tool calls."""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from ..core.netcheck import BLOCKED_HOSTNAMES, coerce_ip, is_internal_ip


def validate_http_url(url: str, *, resolve_dns: bool = True) -> str | None:
    """Return None if `url` is safe, or a reason string if it should be blocked.

    Blocks: non-http(s) schemes, RFC1918 / loopback / link-local / metadata
    hosts (including decimal-, hex-, and IPv6-encoded forms), and (when DNS
    resolution is allowed) hostnames that resolve to blocked IPs.
    """
    if not isinstance(url, str) or not url.strip():
        return "empty url"

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return f"scheme {parsed.scheme!r} is not allowed"

    host = (parsed.hostname or "").lower()
    if not host:
        return "url has no host"

    if host.rstrip(".") in BLOCKED_HOSTNAMES:
        return f"hostname {host!r} is blocked (cloud metadata)"

    addr = coerce_ip(host)
    if addr is not None:
        if is_internal_ip(addr):
            return f"host {host!r} is in a blocked IP range"
    elif resolve_dns:
        try:
            for _family, _stype, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                resolved = coerce_ip(sockaddr[0])
                if resolved is not None and is_internal_ip(resolved):
                    return f"hostname {host!r} resolves to blocked IP {sockaddr[0]!r}"
        except socket.gaierror:
            return f"hostname {host!r} could not be resolved"

    return None
