"""Shared pytest fixtures for unit and integration tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.torrent.store import TorrentSessionStore


@pytest.fixture()
def test_settings() -> Settings:
    """Isolated settings binding ephemeral ports on 127.0.0.1."""
    return Settings(
        bind_host="127.0.0.1",
        udp_tracker_enabled=True,
        udp_tracker_port=0,
        peer_server_enabled=True,
        peer_server_port=0,
        strict_ports=True,
        trust_proxy_headers=False,
        session_ttl_seconds=900,
        max_sessions=100,
    )


@pytest.fixture()
def session_store() -> TorrentSessionStore:
    return TorrentSessionStore(ttl_seconds=900, max_sessions=100)


@pytest.fixture()
def client(
    test_settings: Settings,
    session_store: TorrentSessionStore,
) -> Iterator[TestClient]:
    application = create_app(settings=test_settings, store=session_store)
    with TestClient(application, client=("93.184.216.34", 54321)) as test_client:
        yield test_client

