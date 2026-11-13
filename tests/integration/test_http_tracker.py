"""Integration tests for BEP 3 / BEP 23 / BEP 48 HTTP tracker announce and scrape."""

from __future__ import annotations

import socket
import struct
import urllib.parse

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.torrent.bencode import bdecode


def _percent_encode_bytes(raw: bytes) -> str:
    return urllib.parse.quote_from_bytes(raw, safe="")


def test_http_announce_records_binary_info_hash_and_returns_compact_peer() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        public_ipv4="127.0.0.1",
        udp_tracker_port=0,
        peer_server_port=0,
        peer_probe_enabled=False,
    )
    app = create_app(settings=settings)

    with TestClient(app, client=("198.51.100.42", 51413)) as torrent_client:
        session = torrent_client.post("/api/torrent/sessions").json()
        token = session["token"]
        info_hash_bytes = bytes.fromhex(session["info_hash"])
        peer_id_bytes = b"-qB4650-\xff\xfe\x80\x0012345678"

        qs = (
            f"info_hash={_percent_encode_bytes(info_hash_bytes)}"
            f"&peer_id={_percent_encode_bytes(peer_id_bytes)}"
            "&port=51413&uploaded=0&downloaded=0&left=0&compact=1&event=started"
            "&ip=203.0.113.99"
        )
        announce_resp = torrent_client.get(
            f"/announce/{token}?{qs}",
            headers={"User-Agent": "qBittorrent/4.6.5"},
        )
        assert announce_resp.status_code == 200

        tracker_dict = bdecode(announce_resp.content)
        assert tracker_dict[b"interval"] == 60
        assert tracker_dict[b"complete"] == 1
        assert len(tracker_dict[b"peers"]) == 6
        peer_ip = socket.inet_ntoa(tracker_dict[b"peers"][:4])
        peer_port = struct.unpack("!H", tracker_dict[b"peers"][4:6])[0]
        assert peer_ip == "127.0.0.1"
        assert peer_port == app.state.peer_server.bound_port
        assert tracker_dict[b"peers6"] == b""

        status = torrent_client.get(f"/api/torrent/sessions/{token}").json()
        assert len(status["detections"]) == 1
        det = status["detections"][0]
        assert det["ip"] == "198.51.100.42"
        assert det["port"] == 51413
        assert det["source"] == "http_tracker"
        assert det["client"] == "qBittorrent/4.6.5"
        assert det["reported_ips"] == ["203.0.113.99"]
        assert status["summary"]["reported_mismatch_ips"] == ["203.0.113.99"]
        assert status["summary"]["has_multi_ip_leak"] is True


def test_http_announce_returns_ipv4_and_ipv6_peers() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        public_host="leak.example.com",
        public_ipv4="203.0.113.10",
        public_ipv6="2001:db8::10",
        udp_tracker_enabled=False,
        peer_server_port=0,
        strict_ports=True,
        peer_probe_enabled=False,
    )
    app = create_app(settings=settings)
    with TestClient(app, client=("198.51.100.42", 51413)) as torrent_client:
        session = torrent_client.post("/api/torrent/sessions").json()
        peers = session["peers"]
        assert any(peer.startswith("leak.example.com:") for peer in peers)
        assert any(peer.startswith("203.0.113.10:") for peer in peers)
        assert any(peer.startswith("[2001:db8::10]:") for peer in peers)

        info_hash = _percent_encode_bytes(bytes.fromhex(session["info_hash"]))
        announce = torrent_client.get(
            f"/announce/{session['token']}?info_hash={info_hash}&port=6881&compact=1"
        )
        decoded = bdecode(announce.content)
        assert socket.inet_ntoa(decoded[b"peers"][:4]) == "203.0.113.10"
        assert socket.inet_ntop(socket.AF_INET6, decoded[b"peers6"][:16]) == "2001:db8::10"
        assert len(decoded[b"peers6"]) == 18

        listed = torrent_client.get(
            f"/announce/{session['token']}?info_hash={session['info_hash']}&compact=0&port=6881"
        )
        peer_ips = {peer[b"ip"] for peer in bdecode(listed.content)[b"peers"]}
        assert peer_ips == {b"203.0.113.10", b"2001:db8::10"}


def test_localhost_dual_stack_magnet_includes_ipv6_peer() -> None:
    settings = Settings(
        bind_host="::",
        udp_tracker_port=0,
        peer_server_port=0,
        strict_ports=True,
        peer_probe_enabled=False,
    )
    app = create_app(settings=settings)
    with TestClient(app, base_url="http://localhost:8000") as local_client:
        session = local_client.post("/api/torrent/sessions").json()
        assert any(peer.startswith("127.0.0.1:") for peer in session["peers"])
        assert any(peer.startswith("[::1]:") for peer in session["peers"])


def test_announce_probe_uses_socket_ip_not_forwarded_header() -> None:
    settings = Settings(
        bind_host="127.0.0.1",
        udp_tracker_enabled=False,
        peer_server_port=0,
        strict_ports=True,
        peer_probe_enabled=True,
        peer_probe_timeout=0.2,
        trust_proxy_headers=True,
    )
    app = create_app(settings=settings)
    with TestClient(app, client=("203.0.113.10", 40000)) as torrent_client:
        session = torrent_client.post(
            "/api/torrent/sessions",
            headers={"X-Forwarded-For": "203.0.113.10"},
        ).json()
        info_hash = _percent_encode_bytes(bytes.fromhex(session["info_hash"]))
        announce = torrent_client.get(
            f"/announce/{session['token']}?info_hash={info_hash}&port=51413",
            headers={"X-Forwarded-For": "8.8.8.8"},
        )
        assert announce.status_code == 200
        status = torrent_client.get(f"/api/torrent/sessions/{session['token']}").json()
        assert status["detections"][0]["ip"] == "8.8.8.8"
        assert all(not key.startswith("8.8.8.8") for key in status["peer_probes"])
        assert status["peer_probes"] == {}


def test_http_announce_supports_non_compact_and_failure_cases(client: TestClient) -> None:
    # Missing info_hash
    missing_resp = client.get("/announce")
    assert b"failure reason" in bdecode(missing_resp.content)

    # Unknown session info_hash
    unknown_hash = _percent_encode_bytes(b"\xaa" * 20)
    unknown_resp = client.get(f"/announce?info_hash={unknown_hash}")
    assert b"failure reason" in bdecode(unknown_resp.content)

    # Valid session with compact=0 and 40-char hex info_hash convenience
    session = client.post("/api/torrent/sessions").json()
    non_compact_resp = client.get(
        f"/announce?info_hash={session['info_hash']}&compact=0&port=6881",
        headers={"User-Agent": "Transmission/4.0.6"},
    )
    decoded = bdecode(non_compact_resp.content)
    assert isinstance(decoded[b"peers"], list)


def test_http_scrape_records_hit_and_returns_files_dict(client: TestClient) -> None:
    session = client.post("/api/torrent/sessions").json()
    ih_bytes = bytes.fromhex(session["info_hash"])
    qs = f"info_hash={_percent_encode_bytes(ih_bytes)}"

    scrape_resp = client.get(
        f"/scrape/{session['token']}?{qs}",
        headers={"User-Agent": "Deluge/2.1.1"},
    )
    assert scrape_resp.status_code == 200
    decoded = bdecode(scrape_resp.content)
    assert ih_bytes in decoded[b"files"]

    status = client.get(f"/api/torrent/sessions/{session['token']}").json()
    assert len(status["detections"]) == 1
    assert status["detections"][0]["source"] == "http_scrape"

    # Token-only scrape without info_hash query param also records scrape hit
    session2 = client.post("/api/torrent/sessions").json()
    token_only_resp = client.get(f"/scrape/{session2['token']}")
    assert token_only_resp.status_code == 200
    assert bytes.fromhex(session2["info_hash"]) in bdecode(token_only_resp.content)[b"files"]
