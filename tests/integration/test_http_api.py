"""Integration tests for static UI serving, client IP API, and session creation."""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.torrent.bencode import bdecode, bencode


def test_serves_frontend_and_js_modules(client: TestClient) -> None:
    index_resp = client.get("/")
    assert index_resp.status_code == 200
    assert "IP Leak Check" in index_resp.text
    assert "/static/js/app.js" in index_resp.text
    assert "Related" in index_resp.text
    assert 'id="session-expiry"' in index_resp.text

    for asset in (
        "/static/styles.css",
        "/static/js/app.js",
        "/static/js/webrtc.js",
        "/static/js/torrent.js",
    ):
        resp = client.get(asset)
        assert resp.status_code == 200, f"Failed to load static asset {asset}"


def test_get_client_ip_direct_ignores_spoofed_headers_by_default(client: TestClient) -> None:
    resp = client.get(
        "/api/ip",
        headers={
            "X-Forwarded-For": "1.1.1.1",
            "User-Agent": "Mozilla/5.0 TestBrowser",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ip"] == "93.184.216.34"
    assert body["version"] == 4
    assert body["scope"] == "public"
    assert body["is_public"] is True
    assert body["detected_via"] == "direct"
    assert body["user_agent"] == "Mozilla/5.0 TestBrowser"


def test_get_client_ip_honors_proxy_headers_when_enabled() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        udp_tracker_enabled=False,
        peer_server_enabled=False,
        trust_proxy_headers=True,
    )
    app = create_app(settings=settings)
    with TestClient(app, client=("10.0.0.2", 50000)) as proxy_client:
        resp = proxy_client.get(
            "/api/ip",
            headers={"X-Forwarded-For": "2606:4700:4700::1111, 10.0.0.2"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ip"] == "2606:4700:4700::1111"
        assert body["version"] == 6
        assert body["is_public"] is True
        assert body["detected_via"] == "x-forwarded-for"

        resp_real_ip = proxy_client.get("/api/ip", headers={"X-Real-IP": "8.8.4.4"})
        assert resp_real_ip.json()["ip"] == "8.8.4.4"
        assert resp_real_ip.json()["detected_via"] == "x-real-ip"


def test_classify_addresses_uses_server_scopes(client: TestClient) -> None:
    resp = client.post(
        "/api/ip/classify",
        json={
            "addresses": [
                "8.8.8.8",
                "100.64.10.1",
                "203.0.113.10",
                "host.local",
                "not-an-ip",
                "169.254.1.1",
            ]
        },
    )
    assert resp.status_code == 200
    by_input = {row["input"]: row for row in resp.json()["results"]}
    assert by_input["8.8.8.8"]["scope"] == "public"
    assert by_input["8.8.8.8"]["is_public"] is True
    assert by_input["100.64.10.1"]["scope"] == "private"
    assert by_input["100.64.10.1"]["is_public"] is False
    assert by_input["203.0.113.10"]["scope"] == "reserved"
    assert by_input["host.local"]["scope"] == "mdns"
    assert by_input["not-an-ip"]["scope"] == "unknown"
    assert by_input["169.254.1.1"]["scope"] == "link_local"

    too_many = client.post("/api/ip/classify", json={"addresses": ["1.1.1.1"] * 65})
    assert too_many.status_code == 422
    too_long = client.post("/api/ip/classify", json={"addresses": ["x" * 129]})
    assert too_long.status_code == 422


def test_session_creation_is_rate_limited_per_ip() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        udp_tracker_enabled=False,
        peer_server_enabled=False,
        session_create_limit=2,
        session_create_window_seconds=300,
    )
    app = create_app(settings=settings)
    with TestClient(app, client=("198.51.100.8", 1234)) as limited:
        assert limited.post("/api/torrent/sessions").status_code == 201
        assert limited.post("/api/torrent/sessions").status_code == 201
        blocked = limited.post("/api/torrent/sessions")
        assert blocked.status_code == 429
        assert "Too many" in blocked.json()["detail"]
        assert blocked.headers["retry-after"] == "300"


def test_create_and_fetch_torrent_session(client: TestClient) -> None:
    create_resp = client.post("/api/torrent/sessions")
    assert create_resp.status_code == 201
    session = create_resp.json()

    assert len(session["token"]) == 16
    assert len(session["info_hash"]) == 40
    assert session["creator_ip"] == "93.184.216.34"
    assert session["magnet_uri"].startswith(f"magnet:?xt=urn:btih:{session['info_hash']}")
    assert len(session["trackers"]) == 2
    assert any(tr.startswith("http://") for tr in session["trackers"])
    assert any(tr.startswith("udp://") for tr in session["trackers"])
    assert len(session["peers"]) == 1

    get_resp = client.get(f"/api/torrent/sessions/{session['token']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["info_hash"] == session["info_hash"]

    missing_resp = client.get("/api/torrent/sessions/nonexistent")
    assert missing_resp.status_code == 404

    # Verify downloadable .torrent file matches session info_hash
    torrent_resp = client.get(session["torrent_url"])
    assert torrent_resp.status_code == 200
    assert torrent_resp.headers["content-type"] == "application/x-bittorrent"
    assert session["display_name"] in torrent_resp.headers["content-disposition"]
    metainfo = bdecode(torrent_resp.content)
    assert hashlib.sha1(bencode(metainfo[b"info"])).hexdigest() == session["info_hash"]

    assert client.get("/api/torrent/sessions/nonexistent/torrent").status_code == 404


def test_localhost_request_normalizes_magnet_endpoints_to_ipv4_loopback() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        udp_tracker_port=0,
        peer_server_port=0,
    )
    app = create_app(settings=settings)
    with TestClient(app, base_url="http://localhost:8000") as local_client:
        session = local_client.post("/api/torrent/sessions").json()
        assert session["trackers"][0].startswith("http://127.0.0.1:8000/announce/")
        assert session["trackers"][1].startswith("udp://127.0.0.1:")
        assert session["peers"][0].startswith("127.0.0.1:")

