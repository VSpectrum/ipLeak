"""Lightweight BEP 3 TCP BitTorrent peer wire listener for direct peer IP leak detection."""

from __future__ import annotations

import asyncio
import logging
import secrets

from app.ip_utils import normalize_ip
from app.torrent.magnet import decode_peer_id
from app.torrent.store import TorrentSessionStore

logger = logging.getLogger(__name__)

BT_HANDSHAKE_PREFIX = b"\x13BitTorrent protocol"
BT_HANDSHAKE_LENGTH = 68


class PeerWireServer:
    """Asyncio TCP server accepting 68-byte BitTorrent peer handshakes."""

    def __init__(
        self,
        store: TorrentSessionStore,
        *,
        host: str = "0.0.0.0",
        port: int = 6889,
        strict_ports: bool = False,
        handshake_timeout: float = 5.0,
    ) -> None:
        self.store = store
        self.host = host
        self.configured_port = port
        self.strict_ports = strict_ports
        self.handshake_timeout = handshake_timeout
        self._peer_id = b"-IL0100-" + secrets.token_hex(6).encode("ascii")
        self._server: asyncio.Server | None = None
        self.bound_port: int | None = None

    async def start(self) -> int:
        try:
            server = await asyncio.start_server(
                self._handle_client,
                host=self.host,
                port=self.configured_port,
            )
        except OSError as exc:
            if self.strict_ports or self.configured_port == 0:
                raise
            logger.warning(
                "TCP peer port %d unavailable (%s); falling back to ephemeral TCP port",
                self.configured_port,
                exc,
            )
            server = await asyncio.start_server(
                self._handle_client,
                host=self.host,
                port=0,
            )

        self._server = server
        sockets = server.sockets or []
        if not sockets:
            raise RuntimeError("PeerWireServer started without bound sockets")
        self.bound_port = int(sockets[0].getsockname()[1])
        logger.info("TCP BitTorrent peer listener active on %s:%d", self.host, self.bound_port)
        return self.bound_port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self.bound_port = None

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            peername = writer.get_extra_info("peername")
            if not peername:
                return
            client_ip = normalize_ip(str(peername[0])) or str(peername[0])
            remote_port = int(peername[1])

            handshake = await asyncio.wait_for(
                reader.readexactly(BT_HANDSHAKE_LENGTH),
                timeout=self.handshake_timeout,
            )
            if handshake[:20] != BT_HANDSHAKE_PREFIX:
                return

            info_hash_bytes = handshake[28:48]
            peer_id_bytes = handshake[48:68]

            matched_session = self.store.record_hit(
                ip=client_ip,
                port=remote_port,
                source="bt_peer",
                info_hash=info_hash_bytes.hex(),
                client=decode_peer_id(peer_id_bytes),
            )
            if matched_session is not None:
                reply = BT_HANDSHAKE_PREFIX + (b"\x00" * 8) + info_hash_bytes + self._peer_id
                writer.write(reply)
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
