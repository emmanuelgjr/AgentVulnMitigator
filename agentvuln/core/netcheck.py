"""Shared SSRF target checks (stdlib-only, no intra-package imports).

Both the analyzer's SSRF *detection* rule and the HTTP tool *validator*
need the same answer to one question: "does this URL host point at an
internal / loopback / cloud-metadata target?" Centralising it here keeps
the two in sync and covers the standard obfuscations (IPv6, bare-decimal,
and hex-encoded IPs) that a literal host list misses.
"""
from __future__ import annotations

import ipaddress

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata",
        "instance-data",
    }
)

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _parse_inet_aton(host: str) -> ipaddress.IPv4Address | None:
    """Parse the loose IPv4 forms `inet_aton`/glibc accept but
    `ipaddress.ip_address` rejects: octal (``0177.0.0.1``), hex parts,
    and short forms (``127.1`` -> ``127.0.0.1``, ``2130706433``)."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values: list[int] = []
    for part in parts:
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                value = int(part, 8)
            else:
                value = int(part)
        except ValueError:
            return None
        if value < 0:
            return None
        values.append(value)

    n = len(values)
    # Each form lets the final part absorb the remaining low-order bytes.
    limits = {1: [0xFFFFFFFF], 2: [0xFF, 0xFFFFFF], 3: [0xFF, 0xFF, 0xFFFF], 4: [0xFF] * 4}
    if any(v > lim for v, lim in zip(values, limits[n], strict=True)):
        return None
    shifts = {1: [0], 2: [24, 0], 3: [24, 16, 0], 4: [24, 16, 8, 0]}[n]
    packed = 0
    for value, shift in zip(values, shifts, strict=True):
        packed |= value << shift
    return ipaddress.IPv4Address(packed)


def coerce_ip(host: str) -> _IpAddress | None:
    """Best-effort parse of a URL host into an IP address.

    Covers the common SSRF-bypass encodings: dotted-quad, IPv6 (with or
    without brackets / zone id), trailing-dot FQDNs, bare decimal
    (``2130706433``), hex (``0x7f000001``), octal (``0177.0.0.1``), and
    short forms (``127.1``). Returns None for genuine hostnames.
    """
    if not host:
        return None
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if "%" in h:  # strip IPv6 zone id, e.g. fe80::1%eth0
        h = h.split("%", 1)[0]
    h = h.rstrip(".")  # trailing-dot FQDN, e.g. 169.254.169.254.
    if not h:
        return None

    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    return _parse_inet_aton(h)


def is_internal_ip(addr: _IpAddress) -> bool:
    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) so the v4 classification
    # applies rather than the v6 address's (which is not is_loopback).
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def is_blocked_host(host: str) -> bool:
    """True if `host` is a metadata/loopback/internal target, whether named
    literally or expressed via any common IP-obfuscation encoding."""
    if not host:
        return False
    if host.strip().rstrip(".").lower() in BLOCKED_HOSTNAMES:
        return True
    addr = coerce_ip(host)
    return addr is not None and is_internal_ip(addr)
