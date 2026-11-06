"""Utilities for extracting, normalizing, and classifying IPv4/IPv6 addresses."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from fastapi import Request

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT (RFC 6598)
)
_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


@dataclass(frozen=True, slots=True)
class IPInfo:
    """Normalized IP metadata."""

    ip: str
    version: int | None
    scope: str
    is_public: bool


def normalize_ip(raw: str | None) -> str | None:
    """Parse and canonicalize an IPv4/IPv6 literal, unwrapping IPv4-mapped IPv6 addresses.

    Returns None when ``raw`` is empty or not a valid IP address literal.
    """
    if not raw:
        return None

    candidate = raw.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]

    # Strip IPv6 zone identifier if present (e.g. fe80::1%eth0)
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return str(ip_obj.ipv4_mapped)

    return str(ip_obj)


def classify_ip(raw: str) -> IPInfo:
    """Classify an IP string into version (4/6) and network scope."""
    normalized = normalize_ip(raw)
    if normalized is None:
        return IPInfo(ip=raw or "unknown", version=None, scope="unknown", is_public=False)

    ip_obj = ipaddress.ip_address(normalized)

    if ip_obj.is_loopback:
        scope = "loopback"
    elif ip_obj.is_link_local:
        scope = "link_local"
    elif (
        isinstance(ip_obj, ipaddress.IPv4Address)
        and any(ip_obj in net for net in _RFC1918_NETWORKS)
    ) or (isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _ULA_NETWORK):
        scope = "private"
    elif ip_obj.is_global:
        scope = "public"
    else:
        scope = "reserved"

    return IPInfo(
        ip=normalized,
        version=ip_obj.version,
        scope=scope,
        is_public=(scope == "public"),
    )


def extract_client_ip(request: Request, *, trust_proxy_headers: bool = False) -> tuple[str, str]:
    """Return ``(client_ip, source)`` for an incoming FastAPI HTTP request."""
    if trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            for part in xff.split(","):
                ip = normalize_ip(part)
                if ip is not None:
                    return ip, "x-forwarded-for"

        for header_name in ("cf-connecting-ip", "x-real-ip"):
            header_val = request.headers.get(header_name)
            ip = normalize_ip(header_val)
            if ip is not None:
                return ip, header_name

    raw_host = request.client.host if request.client else None
    normalized = normalize_ip(raw_host)
    if normalized is not None:
        return normalized, "direct"
    return (raw_host or "unknown"), "direct"


def resolve_peer_ipv4(host: str | None, configured_ipv4: str | None = None) -> str | None:
    """Return a literal IPv4 address suitable for compact 6-byte tracker peer entries."""
    for candidate in (configured_ipv4, "127.0.0.1" if host == "localhost" else host):
        normalized = normalize_ip(candidate)
        if normalized is not None:
            ip_obj = ipaddress.ip_address(normalized)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return normalized
    return None
