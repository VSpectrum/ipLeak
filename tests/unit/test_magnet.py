"""Unit tests for Magnet URI construction and peer_id client decoding."""

from __future__ import annotations

import urllib.parse

import pytest

from app.torrent.magnet import build_magnet_uri, decode_peer_id, format_host_port


def test_format_host_port() -> None:
    assert format_host_port("127.0.0.1", 6889) == "127.0.0.1:6889"
    assert format_host_port("ipleak.example.com", 6969) == "ipleak.example.com:6969"
    assert format_host_port("::1", 6889) == "[::1]:6889"
    assert format_host_port("[::1]", 6889) == "[::1]:6889"


def test_build_magnet_uri_encodes_trackers_and_peers() -> None:
    info_hash = "A1B2C3D4E5" * 4
    uri = build_magnet_uri(
        info_hash,
        display_name="ipleak check #1",
        trackers=[
            "http://127.0.0.1:8000/announce/tok123",
            "udp://127.0.0.1:6969/announce",
        ],
        peers=["127.0.0.1:6889", "[::1]:6889"],
    )

    assert uri.startswith(f"magnet:?xt=urn:btih:{info_hash.lower()}&")
    parsed = urllib.parse.parse_qs(uri.removeprefix("magnet:?"))
    assert parsed["xt"] == [f"urn:btih:{info_hash.lower()}"]
    assert parsed["dn"] == ["ipleak check #1"]
    assert parsed["tr"] == [
        "http://127.0.0.1:8000/announce/tok123",
        "udp://127.0.0.1:6969/announce",
    ]
    assert parsed["x.pe"] == ["127.0.0.1:6889", "[::1]:6889"]


@pytest.mark.parametrize("bad_hash", ["short", "z" * 40, ""])
def test_build_magnet_uri_rejects_invalid_info_hash(bad_hash: str) -> None:
    with pytest.raises(ValueError):
        build_magnet_uri(bad_hash, display_name="test", trackers=[])


def test_decode_peer_id_identifies_popular_clients() -> None:
    assert decode_peer_id(b"-qB4650-abcdefghijkl") == "qBittorrent 4.6.5"
    assert decode_peer_id(b"-TR4060-123456789012") == "Transmission 4.0.6"
    assert decode_peer_id(b"-DE211s-123456789012") == "Deluge 2.1.1s"
    assert decode_peer_id(b"M7-9-2--abcdefghijkl") == "BitTorrent 7.9.2"
    assert decode_peer_id(b"TIX0291-abcdefghijkl") == "Tixati 0.2.9.1"
    assert (
        decode_peer_id(b"-qB4650-abcdefghijkl", user_agent="qBittorrent/4.6.5")
        == "qBittorrent/4.6.5"
    )
    assert decode_peer_id(None) == "Unknown BitTorrent Client"
    assert decode_peer_id(b"\x00\x01\x02") == "Unknown BitTorrent Client"

