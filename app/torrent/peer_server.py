"""BEP 3 TCP BitTorrent peer wire listener (dual-stack) and active outbound peer prober."""

from __future__ import annotations

import asyncio
import logging
import secrets
import socket

from app.ip_utils import bind_listener_socket, is_probeable_ip, normalize_ip
from app.torrent.magnet import decode_peer_id, format_host_port
from app.torrent.store import TorrentSessionStore

logger = logging.getLogger(__name__)

BT_HANDSHAKE_PREFIX = b"\x13BitTorrent protocol"
BT_HANDSHAKE_LENGTH = 68


class PeerWireServer:
    """Asyncio TCP server accepting 68-byte BitTorrent peer handshakes and probing peers."""

    def __init__(
        self,
        store: TorrentSessionStore,
        *,
        host: str = "::",
        port: int = 6889,
        strict_ports: bool = False,
        handshake_timeout: float = 5.0,
        probe_enabled: bool = True,
        probe_timeout: float = 2.0,
        max_in_flight_probes: int = 8,
    ) -> None:
        self.store = store
        self.host = host
        self.configured_port = port
        self.strict_ports = strict_ports
        self.handshake_timeout = handshake_timeout
        self.probe_enabled = probe_enabled
        self.probe_timeout = probe_timeout
        self.max_in_flight_probes = max_in_flight_probes
        self._peer_id = b"-IL0100-" + secrets.token_hex(6).encode("ascii")
        self._server: asyncio.Server | None = None
        self._probe_tasks: set[asyncio.Task[None]] = set()
        self.bound_port: int | None = None

    async def start(self) -> int:
        try:
            sock = bind_listener_socket(self.host, self.configured_port, socket.SOCK_STREAM)
        except OSError as exc:
            if self.strict_ports or self.configured_port == 0:
                raise
            logger.warning(
                "TCP peer port %d unavailable (%s); falling back to ephemeral TCP port",
                self.configured_port,
                exc,
            )
            sock = bind_listener_socket(self.host, 0, socket.SOCK_STREAM)

        server = await asyncio.start_server(self._handle_client, sock=sock)
        self._server = server
        sockets = server.sockets or []
        if not sockets:
            raise RuntimeError("PeerWireServer started without bound sockets")
        self.bound_port = int(sockets[0].getsockname()[1])
        logger.info("TCP BitTorrent peer listener active on [%s]:%d", self.host, self.bound_port)
        return self.bound_port

    async def stop(self) -> None:
        if self._probe_tasks:
            for task in list(self._probe_tasks):
                task.cancel()
            await asyncio.gather(*self._probe_tasks, return_exceptions=True)
            self._probe_tasks.clear()

        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self.bound_port = None

    def schedule_outbound_probe(
        self,
        info_hash: str,
        ip: str,
        port: int,
    ) -> asyncio.Task[None] | None:
        """Schedule a non-blocking outbound TCP BitTorrent handshake to an announced client port."""
        if not self.probe_enabled or not (1 <= port <= 65535):
            return None

        norm_ip = normalize_ip(ip)
        if norm_ip is None or not is_probeable_ip(norm_ip):
            return None

        if self.bound_port and port == self.bound_port and norm_ip in {"127.0.0.1", "::1"}:
            return None

        endpoint = format_host_port(norm_ip, port)
        if not self.store.claim_peer_probe(
            info_hash,
            endpoint,
            max_in_flight=self.max_in_flight_probes,
        ):
            return None

        task = asyncio.create_task(self._run_outbound_probe(info_hash, norm_ip, port, endpoint))
        self._probe_tasks.add(task)
        task.add_done_callback(self._probe_tasks.discard)
        return task

    async def _run_outbound_probe(
        self,
        info_hash: str,
        ip: str,
        port: int,
        endpoint: str,
    ) -> None:
        writer: asyncio.StreamWriter | None = None
        info_hash_bytes = bytes.fromhex(info_hash)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.probe_timeout,
            )
            handshake = BT_HANDSHAKE_PREFIX + (b"\x00" * 8) + info_hash_bytes + self._peer_id
            writer.write(handshake)
            await writer.drain()

            reply = await asyncio.wait_for(
                reader.readexactly(BT_HANDSHAKE_LENGTH),
                timeout=self.probe_timeout,
            )
            if reply[:20] == BT_HANDSHAKE_PREFIX and reply[28:48] == info_hash_bytes:
                self.store.update_peer_probe(info_hash, endpoint, "open")
                self.store.record_hit(
                    ip=ip,
                    port=port,
                    source="bt_peer_outbound",
                    info_hash=info_hash,
                    client=decode_peer_id(reply[48:68]),
                )
            else:
                self.store.update_peer_probe(info_hash, endpoint, "closed")
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            self.store.update_peer_probe(info_hash, endpoint, "closed")
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

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
