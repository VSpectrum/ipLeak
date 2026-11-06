"""Integration tests for static UI serving, client IP API, and session creation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_serves_frontend_and_js_modules(client: TestClient) -> None:
    index_resp = client.get("/")
    assert index_resp.status_code == 200
    assert "IP Leak Check" in index_resp.text
    assert "/static/js/app.js" in index_resp.text

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

