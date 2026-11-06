"""Integration tests for the BEP 15 UDP BitTorrent tracker listener."""

from __future__ import annotations

import asyncio
import socket
import struct

from app.torrent.store import TorrentSessionStore
from app.torrent.udp_tracker import (
    ACTION_ANNOUNCE,
    ACTION_CONNECT,
    ACTION_ERROR,
    ACTION_SCRAPE,
    BEP15_PROTOCOL_ID,
    UDPTrackerServer,
)


class _UDPTestClient(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.inbox: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.inbox.put_nowait(data)


async def _udp_exchange(port: int, payload: bytes) -> bytes:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(
        _UDPTestClient,
        remote_addr=("127.0.0.1", port),
    )
    try:
        transport.sendto(payload)
        return await asyncio.wait_for(proto.inbox.get(), timeout=2.0)
    finally:
        transport.close()


async def test_udp_tracker_connect_announce_scrape_and_error_handling() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    session = store.create_session(creator_ip="127.0.0.1", trackers=[])
    info_hash_bytes = bytes.fromhex(session.info_hash)

    udp_server = UDPTrackerServer(
        store,
        host="127.0.0.1",
        port=0,
        strict_ports=True,
        peer_port_getter=lambda: 6889,
    )
    udp_port = await udp_server.start()

    try:
        # 1. Forged connection_id is rejected with ACTION_ERROR (3)
        forged_announce = struct.pack("!QII", 0xDEADBEEFCAFEBABE, ACTION_ANNOUNCE, 777) + (
            b"\x00" * 82
        )
        err_resp = await _udp_exchange(udp_port, forged_announce)
        err_action, err_tx = struct.unpack("!II", err_resp[:8])
        assert err_action == ACTION_ERROR
        assert err_tx == 777
        assert len(session.detections) == 0

        # 2. Valid BEP 15 Connect handshake
        tx_connect = 1001
        connect_req = struct.pack("!QII", BEP15_PROTOCOL_ID, ACTION_CONNECT, tx_connect)
        connect_resp = await _udp_exchange(udp_port, connect_req)
        resp_action, resp_tx, conn_id = struct.unpack("!IIQ", connect_resp)
        assert resp_action == ACTION_CONNECT
        assert resp_tx == tx_connect

        # 3. Valid BEP 15 Announce with self-reported IPv4 (8.8.8.8)
        tx_announce = 1002
        peer_id = b"-TR4060-abcdefghijkl"
        self_reported_uint32 = struct.unpack("!I", socket.inet_aton("8.8.8.8"))[0]
        announce_req = (
            struct.pack("!QII", conn_id, ACTION_ANNOUNCE, tx_announce)
            + info_hash_bytes
            + peer_id
            + struct.pack("!QQQ", 0, 0, 0)
            + struct.pack("!IIIiH", 2, self_reported_uint32, 9999, -1, 51413)
        )
        assert len(announce_req) == 98

        announce_resp = await _udp_exchange(udp_port, announce_req)
        assert len(announce_resp) == 26  # 20-byte header + 6-byte compact peer
        a_action, a_tx, interval, leechers, seeders = struct.unpack("!IIIII", announce_resp[:20])
        assert a_action == ACTION_ANNOUNCE
        assert a_tx == tx_announce
        assert interval == 60
        assert leechers == 0
        assert seeders == 1
        assert socket.inet_ntoa(announce_resp[20:24]) == "127.0.0.1"
        assert struct.unpack("!H", announce_resp[24:26])[0] == 6889

        # 4. Valid BEP 15 Scrape
        tx_scrape = 1003
        scrape_req = struct.pack("!QII", conn_id, ACTION_SCRAPE, tx_scrape) + info_hash_bytes
        scrape_resp = await _udp_exchange(udp_port, scrape_req)
        s_action, s_tx, s_seeders, s_completed, s_leechers = struct.unpack("!IIIII", scrape_resp)
        assert s_action == ACTION_SCRAPE
        assert s_tx == tx_scrape
        assert (s_seeders, s_completed, s_leechers) == (1, 0, 0)

        snap = session.to_dict()
        sources = {d["source"]: d for d in snap["detections"]}
        assert "udp_tracker" in sources
        assert sources["udp_tracker"]["ip"] == "127.0.0.1"
        assert sources["udp_tracker"]["port"] == 51413
        assert sources["udp_tracker"]["client"] == "Transmission 4.0.6"
        assert sources["udp_tracker"]["reported_ips"] == ["8.8.8.8"]
        assert "udp_scrape" in sources
    finally:
        await udp_server.stop()


async def test_udp_tracker_falls_back_to_ephemeral_port_when_non_strict() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    primary = UDPTrackerServer(store, host="127.0.0.1", port=0, strict_ports=True)
    occupied_port = await primary.start()
    fallback = UDPTrackerServer(
        store,
        host="127.0.0.1",
        port=occupied_port,
        strict_ports=False,
    )
    try:
        fallback_port = await fallback.start()
        assert fallback_port != occupied_port
        assert fallback_port > 0
    finally:
        await fallback.stop()
        await primary.stop()
