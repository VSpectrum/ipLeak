"""Unit tests for IP normalization, network scope classification, and env config."""

from __future__ import annotations

import pytest

from app.config import load_settings
from app.ip_utils import classify_ip, normalize_ip, resolve_peer_ipv4


def test_normalize_ip_handles_ipv4_ipv6_brackets_zones_and_mapped() -> None:
    assert normalize_ip(" 8.8.8.8 ") == "8.8.8.8"
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip("[2606:4700:4700::1111]") == "2606:4700:4700::1111"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("::ffff:93.184.216.34") == "93.184.216.34"
    assert normalize_ip("") is None
    assert normalize_ip(None) is None
    assert normalize_ip("not-an-ip") is None


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


def test_load_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IPLEAK_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("IPLEAK_PUBLIC_HOST", "leak.example.com")
    monkeypatch.setenv("IPLEAK_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("IPLEAK_UDP_TRACKER_PORT", "7001")
    monkeypatch.setenv("IPLEAK_PEER_SERVER_ENABLED", "false")

    cfg = load_settings()
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.public_host == "leak.example.com"
    assert cfg.trust_proxy_headers is True
    assert cfg.udp_tracker_port == 7001
    assert cfg.peer_server_enabled is False

