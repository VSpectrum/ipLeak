"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw.strip())


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw.strip())


def _env_str(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


@dataclass(slots=True)
class Settings:
    """Runtime configuration for HTTP, UDP tracker, and TCP BitTorrent peer listeners."""

    bind_host: str = "::"
    public_host: str | None = None
    public_http_base_url: str | None = None
    public_ipv4: str | None = None

    udp_tracker_enabled: bool = True
    udp_tracker_port: int = 6969

    peer_server_enabled: bool = True
    peer_server_port: int = 6889

    peer_probe_enabled: bool = True
    peer_probe_timeout: float = 2.0

    strict_ports: bool = False
    trust_proxy_headers: bool = False

    session_ttl_seconds: int = 900
    max_sessions: int = 1000


def load_settings() -> Settings:
    """Create a Settings instance from IPLEAK_* environment variables."""
    return Settings(
        bind_host=os.getenv("IPLEAK_BIND_HOST", "::").strip(),
        public_host=_env_str("IPLEAK_PUBLIC_HOST"),
        public_http_base_url=_env_str("IPLEAK_PUBLIC_HTTP_BASE_URL"),
        public_ipv4=_env_str("IPLEAK_PUBLIC_IPV4"),
        udp_tracker_enabled=_env_bool("IPLEAK_UDP_TRACKER_ENABLED", True),
        udp_tracker_port=_env_int("IPLEAK_UDP_TRACKER_PORT", 6969),
        peer_server_enabled=_env_bool("IPLEAK_PEER_SERVER_ENABLED", True),
        peer_server_port=_env_int("IPLEAK_PEER_SERVER_PORT", 6889),
        peer_probe_enabled=_env_bool("IPLEAK_PEER_PROBE_ENABLED", True),
        peer_probe_timeout=_env_float("IPLEAK_PEER_PROBE_TIMEOUT", 2.0),
        strict_ports=_env_bool("IPLEAK_STRICT_PORTS", False),
        trust_proxy_headers=_env_bool("IPLEAK_TRUST_PROXY_HEADERS", False),
        session_ttl_seconds=_env_int("IPLEAK_SESSION_TTL_SECONDS", 900),
        max_sessions=_env_int("IPLEAK_MAX_SESSIONS", 1000),
    )
