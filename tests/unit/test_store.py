"""Unit tests for TorrentSessionStore creation, deduplication, leak flags, and TTL."""

from __future__ import annotations

from app.torrent.store import TorrentSessionStore


def test_session_creation_and_deduplicated_hits() -> None:
    now = 1_700_000_000.0
    store = TorrentSessionStore(ttl_seconds=300, max_sessions=10, clock=lambda: now)

    session = store.create_session(
        creator_ip="93.184.216.34",
        trackers=["http://127.0.0.1:8000/announce/tok1"],
        peers=["127.0.0.1:6889"],
        token="tok1",
    )
    assert store.get_by_token("tok1") is session
    assert store.get_by_info_hash(session.info_hash.upper()) is session

    # First hit from matching browser IP
    store.record_hit(
        ip="93.184.216.34",
        port=51413,
        source="http_tracker",
        info_hash=session.info_hash,
        client="Unknown BitTorrent Client",
        reported_ips=["0.0.0.0"],  # Unspecified IP should be ignored
    )
    # Second hit from same (ip, source) deduplicates and upgrades client label
    now += 5.0
    store.record_hit(
        ip="::ffff:93.184.216.34",  # IPv4-mapped IPv6 normalizes to same IPv4
        port=51413,
        source="http_tracker",
        info_hash=session.info_hash,
        client="qBittorrent 4.6.5",
    )

    snap = session.to_dict()
    assert len(snap["detections"]) == 1
    assert snap["detections"][0]["hit_count"] == 2
    assert snap["detections"][0]["client"] == "qBittorrent 4.6.5"
    assert snap["detections"][0]["reported_ips"] == []
    assert snap["summary"]["matches_browser_ip"] is True
    assert snap["summary"]["has_multi_ip_leak"] is False


def test_multi_ip_and_reported_param_leak_detection() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    session = store.create_session(
        creator_ip="185.220.101.1",  # Browser on VPN
        trackers=["http://example.com/announce/t1"],
    )

    # HTTP tracker uses VPN IP, but self-reports ISP IPv4 in &ip=
    store.record_hit(
        ip="185.220.101.1",
        source="http_tracker",
        info_hash=session.info_hash,
        reported_ips=["1.1.1.1"],
    )
    # UDP tracker bypasses proxy and connects from 8.8.4.4
    store.record_hit(
        ip="8.8.4.4",
        source="udp_tracker",
        info_hash=session.info_hash,
    )

    snap = session.to_dict()
    assert snap["summary"]["unique_ips"] == ["185.220.101.1", "8.8.4.4"]
    assert snap["summary"]["reported_mismatch_ips"] == ["1.1.1.1"]
    assert snap["summary"]["matches_browser_ip"] is False
    assert snap["summary"]["has_multi_ip_leak"] is True


def test_mismatched_token_and_info_hash_is_rejected() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    s1 = store.create_session(creator_ip="8.8.8.8", trackers=[], token="token_a")
    s2 = store.create_session(creator_ip="8.8.8.8", trackers=[], token="token_b")

    matched = store.record_hit(
        ip="8.8.8.8",
        source="http_tracker",
        info_hash=s1.info_hash,
        token=s2.token,
    )
    assert matched is None
    assert len(s1.detections) == 0
    assert len(s2.detections) == 0


def test_recent_session_count_is_per_ip_and_window() -> None:
    current_time = 1_000.0
    store = TorrentSessionStore(ttl_seconds=900, clock=lambda: current_time)
    store.create_session(creator_ip="1.1.1.1", trackers=[], token="a")
    store.create_session(creator_ip="::ffff:1.1.1.1", trackers=[], token="b")
    store.create_session(creator_ip="8.8.8.8", trackers=[], token="c")

    assert store.recent_session_count("1.1.1.1", 300) == 2
    assert store.recent_session_count("8.8.8.8", 300) == 1

    current_time += 301
    assert store.recent_session_count("1.1.1.1", 300) == 0


def test_claim_peer_probe_caps_in_flight_probes() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    session = store.create_session(creator_ip="8.8.8.8", trackers=[], token="probe")

    assert store.claim_peer_probe(session.info_hash, "8.8.8.8:1", max_in_flight=1) is True
    assert store.claim_peer_probe(session.info_hash, "8.8.8.8:1", max_in_flight=1) is False
    assert store.claim_peer_probe(session.info_hash, "8.8.8.8:2", max_in_flight=1) is False

    store.update_peer_probe(session.info_hash, "8.8.8.8:1", "closed")
    assert store.claim_peer_probe(session.info_hash, "8.8.8.8:2", max_in_flight=1) is True


def test_ttl_expiration_and_max_sessions_eviction() -> None:
    current_time = 1000.0
    store = TorrentSessionStore(
        ttl_seconds=60,
        max_sessions=2,
        clock=lambda: current_time,
    )

    s1 = store.create_session(creator_ip="1.1.1.1", trackers=[], token="t1")
    s2 = store.create_session(creator_ip="1.1.1.1", trackers=[], token="t2")
    s3 = store.create_session(creator_ip="1.1.1.1", trackers=[], token="t3")

    # Max capacity 2 evicted oldest session s1
    assert store.get_by_token(s1.token) is None
    assert store.get_by_info_hash(s1.info_hash) is None
    assert store.get_by_token(s2.token) is not None
    assert store.get_by_token(s3.token) is not None

    # Advance clock past TTL
    current_time += 61.0
    assert store.get_by_token(s2.token) is None
    assert store.get_by_token(s3.token) is None

