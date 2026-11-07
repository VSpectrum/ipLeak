"""Integration tests for the TCP BitTorrent peer server and full end-to-end magnet flow."""

from __future__ import annotations

import asyncio
import struct
import urllib.parse

import httpx

from app.config import Settings
from app.main import create_app
from app.torrent.peer_server import BT_HANDSHAKE_LENGTH, BT_HANDSHAKE_PREFIX, PeerWireServer
from app.torrent.store import TorrentSessionStore
from app.torrent.udp_tracker import ACTION_ANNOUNCE, ACTION_CONNECT, BEP15_PROTOCOL_ID


async def test_peer_wire_server_records_fragmented_handshake_and_ignores_invalid() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    session = store.create_session(creator_ip="127.0.0.1", trackers=[])
    info_hash_bytes = bytes.fromhex(session.info_hash)

    peer_server = PeerWireServer(store, host="127.0.0.1", port=0, strict_ports=True)
    peer_port = await peer_server.start()

    try:
        # 1. Garbage non-BitTorrent TCP connection is dropped without crashing
        bad_reader, bad_writer = await asyncio.open_connection("127.0.0.1", peer_port)
        bad_writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" + (b"x" * 60))
        await bad_writer.drain()
        assert await asyncio.wait_for(bad_reader.read(68), timeout=2.0) == b""
        bad_writer.close()
        await bad_writer.wait_closed()
        assert len(session.detections) == 0

        # 2. Valid 68-byte BitTorrent handshake sent in two TCP fragments
        reader, writer = await asyncio.open_connection("127.0.0.1", peer_port)
        peer_id = b"-qB4650-001122334455"
        handshake = BT_HANDSHAKE_PREFIX + (b"\x00" * 8) + info_hash_bytes + peer_id
        assert len(handshake) == BT_HANDSHAKE_LENGTH

        writer.write(handshake[:25])
        await writer.drain()
        await asyncio.sleep(0.02)
        writer.write(handshake[25:])
        await writer.drain()

        reply = await asyncio.wait_for(reader.readexactly(BT_HANDSHAKE_LENGTH), timeout=2.0)
        assert reply[:20] == BT_HANDSHAKE_PREFIX
        assert reply[28:48] == info_hash_bytes

        writer.close()
        await writer.wait_closed()

        assert len(session.detections) == 1
        det = session.detections[0]
        assert det.ip == "127.0.0.1"
        assert det.source == "bt_peer"
        assert det.client == "qBittorrent 4.6.5"
    finally:
        await peer_server.stop()


async def test_peer_server_falls_back_to_ephemeral_port_when_non_strict() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    primary = PeerWireServer(store, host="127.0.0.1", port=0, strict_ports=True)
    occupied_port = await primary.start()
    fallback = PeerWireServer(
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


async def test_peer_server_dual_stack_and_outbound_peer_probing() -> None:
    store = TorrentSessionStore(ttl_seconds=300)
    session = store.create_session(creator_ip="127.0.0.1", trackers=[])
    ih_bytes = bytes.fromhex(session.info_hash)

    peer_server = PeerWireServer(
        store,
        host="::",
        port=0,
        strict_ports=True,
        probe_enabled=True,
        probe_timeout=1.5,
    )
    peer_port = await peer_server.start()

    # Spin up a mock torrent client peer listener to receive our server's outbound probe
    async def _mock_client_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            incoming = await asyncio.wait_for(
                reader.readexactly(BT_HANDSHAKE_LENGTH),
                timeout=2.0,
            )
            assert incoming[:20] == BT_HANDSHAKE_PREFIX
            assert incoming[28:48] == ih_bytes
            reply = BT_HANDSHAKE_PREFIX + (b"\x00" * 8) + ih_bytes + b"-DE211s-998877665544"
            writer.write(reply)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    mock_client_srv = await asyncio.start_server(_mock_client_handler, host="127.0.0.1", port=0)
    mock_client_port = int(mock_client_srv.sockets[0].getsockname()[1])

    try:
        # 1. Dual-stack inbound peer handshakes from both IPv4 (127.0.0.1) and IPv6 (::1)
        for target_host in ("127.0.0.1", "::1"):
            reader, writer = await asyncio.open_connection(target_host, peer_port)
            writer.write(
                BT_HANDSHAKE_PREFIX + (b"\x00" * 8) + ih_bytes + b"-qB4650-112233445566"
            )
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(BT_HANDSHAKE_LENGTH), timeout=2.0)
            writer.close()
            await writer.wait_closed()

        # 2. Active outbound probe to open mock client port -> records bt_peer_outbound
        open_task = peer_server.schedule_outbound_probe(
            session.info_hash,
            "127.0.0.1",
            mock_client_port,
        )
        assert open_task is not None
        await open_task

        # Duplicate probe to same endpoint is skipped
        assert (
            peer_server.schedule_outbound_probe(session.info_hash, "127.0.0.1", mock_client_port)
            is None
        )

        # 3. Active outbound probe to a closed port -> marks probe as 'closed'
        temp_srv = await asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=0)
        closed_port = int(temp_srv.sockets[0].getsockname()[1])
        temp_srv.close()
        await temp_srv.wait_closed()

        closed_task = peer_server.schedule_outbound_probe(
            session.info_hash,
            "127.0.0.1",
            closed_port,
        )
        assert closed_task is not None
        await closed_task

        snap = session.to_dict()
        assert snap["peer_probes"][f"127.0.0.1:{mock_client_port}"] == "open"
        assert snap["peer_probes"][f"127.0.0.1:{closed_port}"] == "closed"

        outbound_hits = [d for d in snap["detections"] if d["source"] == "bt_peer_outbound"]
        assert len(outbound_hits) == 1
        assert outbound_hits[0]["client"] == "Deluge 2.1.1s"
        assert set(snap["summary"]["unique_ips"]) == {"127.0.0.1", "::1"}
    finally:
        mock_client_srv.close()
        await mock_client_srv.wait_closed()
        await peer_server.stop()


async def test_end_to_end_magnet_generation_and_all_three_bittorrent_transports() -> None:
    """Full end-to-end integration test exercising HTTP tracker, UDP tracker, and TCP peer."""
    settings = Settings(
        bind_host="127.0.0.1",
        public_host="127.0.0.1",
        udp_tracker_port=0,
        peer_server_port=0,
        strict_ports=True,
    )
    app = create_app(settings=settings)

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 52000))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8000",
        ) as http_client:
            # Step 1: Browser loads its HTTP IP
            ip_resp = await http_client.get("/api/ip")
            assert ip_resp.json()["ip"] == "127.0.0.1"

            # Step 2: Browser generates magnet session
            session_resp = await http_client.post("/api/torrent/sessions")
            assert session_resp.status_code == 201
            session_data = session_resp.json()
            token = session_data["token"]
            magnet_uri = session_data["magnet_uri"]

            # Parse magnet URI just as a real BitTorrent client does
            magnet_params = urllib.parse.parse_qs(magnet_uri.removeprefix("magnet:?"))
            xt = magnet_params["xt"][0]
            info_hash_hex = xt.removeprefix("urn:btih:")
            info_hash_bytes = bytes.fromhex(info_hash_hex)
            trackers = magnet_params["tr"]
            x_pe = magnet_params["x.pe"][0]

            http_tr = next(t for t in trackers if t.startswith("http://"))
            udp_tr = next(t for t in trackers if t.startswith("udp://"))

            # Step 3a: Torrent client announces via HTTP Tracker
            http_announce_path = urllib.parse.urlsplit(http_tr).path
            qs = urllib.parse.quote_from_bytes(info_hash_bytes, safe="")
            ann_resp = await http_client.get(
                f"{http_announce_path}?info_hash={qs}&port=6881",
                headers={"User-Agent": "qBittorrent/4.6.5"},
            )
            assert ann_resp.status_code == 200

            # Step 3b: Torrent client announces via UDP Tracker
            udp_parsed = urllib.parse.urlsplit(udp_tr)
            assert udp_parsed.port is not None
            loop = asyncio.get_running_loop()
            inbox: asyncio.Queue[bytes] = asyncio.Queue()

            class _ClientProto(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                    inbox.put_nowait(data)

            udp_transport, _ = await loop.create_datagram_endpoint(
                _ClientProto,
                remote_addr=("127.0.0.1", udp_parsed.port),
            )
            try:
                udp_transport.sendto(struct.pack("!QII", BEP15_PROTOCOL_ID, ACTION_CONNECT, 42))
                conn_pkt = await asyncio.wait_for(inbox.get(), timeout=2.0)
                _, _, conn_id = struct.unpack("!IIQ", conn_pkt)

                ann_pkt = (
                    struct.pack("!QII", conn_id, ACTION_ANNOUNCE, 43)
                    + info_hash_bytes
                    + b"-qB4650-112233445566"
                    + struct.pack("!QQQ", 0, 0, 0)
                    + struct.pack("!IIIiH", 2, 0, 1234, -1, 6881)
                )
                udp_transport.sendto(ann_pkt)
                await asyncio.wait_for(inbox.get(), timeout=2.0)
            finally:
                udp_transport.close()

            # Step 3c: Torrent client connects via TCP Peer Wire Handshake (x.pe)
            peer_host, peer_port_str = x_pe.rsplit(":", 1)
            reader, writer = await asyncio.open_connection(peer_host, int(peer_port_str))
            writer.write(
                BT_HANDSHAKE_PREFIX
                + (b"\x00" * 8)
                + info_hash_bytes
                + b"-qB4650-112233445566"
            )
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(BT_HANDSHAKE_LENGTH), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            # Step 4: Browser polls session endpoint and sees all 3 transports!
            final_status = (await http_client.get(f"/api/torrent/sessions/{token}")).json()
            observed_sources = {d["source"] for d in final_status["detections"]}
            assert observed_sources == {"http_tracker", "udp_tracker", "bt_peer"}
            assert final_status["summary"]["unique_ips"] == ["127.0.0.1"]
            assert final_status["summary"]["matches_browser_ip"] is True
            assert final_status["summary"]["has_multi_ip_leak"] is False
