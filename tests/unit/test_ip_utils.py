"""Unit tests for IP normalization, network scope classification, and env config."""

from __future__ import annotations

import socket

import pytest

from app.config import load_settings
from app.ip_utils import (
    bind_listener_socket,
    classify_ip,
    describe_address,
    ip_family,
    is_probeable_ip,
    normalize_ip,
    pack_compact_peer,
    resolve_peer_ipv4,
    resolve_peer_ipv6,
)
from app.main import enforce_single_process


def test_normalize_ip_handles_ipv4_ipv6_brackets_zones_and_mapped() -> None:
    assert normalize_ip(" 8.8.8.8 ") == "8.8.8.8"
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip("[2606:4700:4700::1111]") == "2606:4700:4700::1111"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("::ffff:93.184.216.34") == "93.184.216.34"
    assert normalize_ip("") is None
    assert normalize_ip(None) is None
    assert normalize_ip("not-an-ip") is None
    assert ip_family("203.0.113.50") == 4
    assert ip_family("2001:db8::50") == 6
    assert ip_family("::ffff:203.0.113.50") == 4
    assert ip_family("not-an-ip") is None


@pytest.mark.parametrize(
    ("raw", "expected_version", "expected_scope", "expected_public"),
    [
        ("8.8.8.8", 4, "public", True),
        ("2606:4700:4700::1111", 6, "public", True),
        ("127.0.0.1", 4, "loopback", False),
        ("::1", 6, "loopback", False),
        ("10.0.0.5", 4, "private", False),
        ("172.16.12.1", 4, "private", False),
        ("192.168.1.25", 4, "private", False),
        ("100.64.10.1", 4, "private", False),
        ("fd12:3456:789a::1", 6, "private", False),
        ("169.254.10.20", 4, "link_local", False),
        ("fe80::abcd%wlan0", 6, "link_local", False),
        ("203.0.113.10", 4, "reserved", False),  # RFC 5737 TEST-NET-3
        ("0.0.0.0", 4, "reserved", False),
        ("224.0.0.1", 4, "reserved", False),
        ("ff02::1", 6, "reserved", False),
        ("testclient", None, "unknown", False),
    ],
)
def test_classify_ip_scopes(
    raw: str,
    expected_version: int | None,
    expected_scope: str,
    expected_public: bool,
) -> None:
    info = classify_ip(raw)
    assert info.version == expected_version
    assert info.scope == expected_scope
    assert info.is_public is expected_public


def test_resolve_peer_ipv4() -> None:
    assert resolve_peer_ipv4("localhost") == "127.0.0.1"
    assert resolve_peer_ipv4("93.184.216.34") == "93.184.216.34"
    assert resolve_peer_ipv4("example.com", configured_ipv4="1.1.1.1") == "1.1.1.1"
    assert resolve_peer_ipv4("example.com") is None
    assert resolve_peer_ipv4("::1") is None


def test_resolve_peer_ipv6_and_compact_pack() -> None:
    assert resolve_peer_ipv6("localhost") == "::1"
    assert resolve_peer_ipv6("example.com", configured_ipv6="2001:db8::10") == "2001:db8::10"
    assert resolve_peer_ipv6("127.0.0.1") is None
    assert resolve_peer_ipv6("2001:db8::1") == "2001:db8::1"

    assert pack_compact_peer("127.0.0.1", 6889) == socket.inet_aton("127.0.0.1") + (6889).to_bytes(
        2, "big"
    )
    packed_v6 = pack_compact_peer("2001:db8::1", 6889)
    assert len(packed_v6) == 18
    assert packed_v6[:16] == socket.inet_pton(socket.AF_INET6, "2001:db8::1")


def test_is_probeable_ip_allows_only_global_unicast() -> None:
    assert is_probeable_ip("8.8.8.8") is True
    assert is_probeable_ip("2606:4700:4700::1111") is True
    assert is_probeable_ip("127.0.0.1") is False
    assert is_probeable_ip("::1") is False
    assert is_probeable_ip("10.1.2.3") is False
    assert is_probeable_ip("100.64.0.1") is False
    assert is_probeable_ip("169.254.169.254") is False
    assert is_probeable_ip("fe80::1") is False
    assert is_probeable_ip("224.0.0.1") is False
    assert is_probeable_ip("203.0.113.10") is False
    assert is_probeable_ip("not-an-ip") is False


def test_describe_address_matches_server_scopes() -> None:
    public = describe_address("8.8.8.8")
    assert public.scope == "public" and public.is_public is True
    assert describe_address("100.64.10.1").scope == "private"
    assert describe_address("203.0.113.10").scope == "reserved"
    assert describe_address("169.254.1.1").scope == "link_local"
    mdns = describe_address("host.local")
    assert mdns.scope == "mdns" and mdns.is_public is False
    assert describe_address("not-an-ip").scope == "unknown"
    assert describe_address("[2001:db8::1]").scope == "reserved"


def test_bind_listener_socket_disables_v6only() -> None:
    sock = bind_listener_socket("::", 0, socket.SOCK_STREAM)
    try:
        assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 0
        assert sock.getsockname()[0] == "::"
    finally:
        sock.close()


def test_enforce_single_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("UVICORN_WORKERS", raising=False)
    enforce_single_process()

    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    enforce_single_process()

    monkeypatch.setenv("UVICORN_WORKERS", "4")
    with pytest.raises(RuntimeError, match="one process"):
        enforce_single_process()


def test_load_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IPLEAK_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("IPLEAK_PUBLIC_HOST", "leak.example.com")
    monkeypatch.setenv("IPLEAK_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("IPLEAK_UDP_TRACKER_PORT", "7001")
    monkeypatch.setenv("IPLEAK_PEER_SERVER_ENABLED", "false")
    monkeypatch.setenv("IPLEAK_PUBLIC_IPV6", "2001:db8::10")
    monkeypatch.setenv("IPLEAK_HTTP_PORT", "8080")
    monkeypatch.setenv("IPLEAK_SESSION_CREATE_LIMIT", "3")
    monkeypatch.setenv("IPLEAK_MAX_IN_FLIGHT_PROBES", "2")

    cfg = load_settings()
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.public_host == "leak.example.com"
    assert cfg.public_ipv6 == "2001:db8::10"
    assert cfg.http_port == 8080
    assert cfg.session_create_limit == 3
    assert cfg.max_in_flight_probes == 2
    assert cfg.trust_proxy_headers is True
    assert cfg.udp_tracker_port == 7001
    assert cfg.peer_server_enabled is False

