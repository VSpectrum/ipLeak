"""Utilities for extracting, normalizing, classifying, and binding IPv4/IPv6 addresses."""

from __future__ import annotations

import ipaddress
import os
import socket
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


def ip_family(raw: str | None) -> int | None:
    """Return 4 or 6 for an IP literal, or None when ``raw`` is not an IP."""
    normalized = normalize_ip(raw)
    if normalized is None:
        return None
    return ipaddress.ip_address(normalized).version


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
    elif ip_obj.is_multicast or ip_obj.is_unspecified:
        scope = "reserved"
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


def resolve_peer_ip(host: str | None, configured: str | None, *, version: int) -> str | None:
    """Return a literal address of ``version`` (4 or 6) for tracker peer lists."""
    loopback = "127.0.0.1" if version == 4 else "::1"
    candidates = [configured, loopback if host == "localhost" else host]
    for candidate in candidates:
        normalized = normalize_ip(candidate)
        if normalized is None:
            continue
        parsed = ipaddress.ip_address(normalized)
        if parsed.version == version:
            return normalized
    return None


def resolve_peer_ipv4(host: str | None, configured_ipv4: str | None = None) -> str | None:
    """Return a literal IPv4 address suitable for compact 6-byte tracker peer entries."""
    return resolve_peer_ip(host, configured_ipv4, version=4)


def resolve_peer_ipv6(host: str | None, configured_ipv6: str | None = None) -> str | None:
    """Return a literal IPv6 address suitable for compact 18-byte peers6 entries."""
    return resolve_peer_ip(host, configured_ipv6, version=6)


def pack_compact_peer(ip: str, port: int) -> bytes:
    """Pack an IP and port into a 6-byte IPv4 peer or an 18-byte IPv6 peer."""
    if not 0 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return ipaddress.ip_address(ip).packed + port.to_bytes(2, "big")


def is_probeable_ip(raw: str | None) -> bool:
    """Return True when an outbound peer probe may connect to this address.

    Probes are limited to global unicast addresses. Loopback, private, link-local,
    multicast, and reserved targets are refused so an announce cannot steer the
    probe at local services or link-local metadata addresses.
    """
    normalized = normalize_ip(raw)
    if normalized is None:
        return False
    parsed = ipaddress.ip_address(normalized)
    return bool(parsed.is_global and not parsed.is_multicast and not parsed.is_unspecified)


def request_socket_ip(request: Request) -> str | None:
    """Return the normalized IP of the TCP socket, ignoring forwarded headers."""
    raw_host = request.client.host if request.client else None
    return normalize_ip(raw_host)


@dataclass(frozen=True, slots=True)
class AddressDescription:
    """Classification of one address submitted by the browser."""

    input: str
    ip: str
    version: int | None
    scope: str
    is_public: bool

    def to_dict(self) -> dict[str, str | int | bool | None]:
        return {
            "input": self.input,
            "ip": self.ip,
            "version": self.version,
            "scope": self.scope,
            "is_public": self.is_public,
        }


def describe_address(raw: str) -> AddressDescription:
    """Classify an IP, mDNS hostname, or other ICE address string."""
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        text = text.split("%", 1)[0]
    if text.lower().endswith(".local"):
        return AddressDescription(raw, text, None, "mdns", False)

    info = classify_ip(text)
    return AddressDescription(raw, info.ip, info.version, info.scope, info.is_public)


def bind_listener_socket(host: str, port: int, sock_kind: socket.SocketKind) -> socket.socket:
    """Create and bind a non-blocking UDP or TCP socket with dual-stack support for '::'."""
    target = host.strip() or "::"

    if target == "::":
        try:
            sock = socket.socket(socket.AF_INET6, sock_kind)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                if sock_kind == socket.SOCK_STREAM and os.name != "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("::", port))
                sock.setblocking(False)
                return sock
            except BaseException:
                sock.close()
                raise
        except OSError as ipv6_exc:
            # Fall back to IPv4 wildcard ONLY if IPv6 itself is disabled/unavailable
            if ipv6_exc.errno not in {
                getattr(socket, "EAFNOSUPPORT", -1),
                getattr(socket, "EPROTONOSUPPORT", -1),
                getattr(socket, "EADDRNOTAVAIL", -1),
            }:
                raise
            target = "0.0.0.0"

    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    sock = socket.socket(family, sock_kind)
    try:
        if sock_kind == socket.SOCK_STREAM and os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((target, port))
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise
