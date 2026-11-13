"""Lightweight BEP 15 UDP BitTorrent tracker listener (dual-stack IPv4/IPv6)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
import socket
import struct
import time
from collections.abc import Callable
from typing import Any

from app.ip_utils import (
    bind_listener_socket,
    normalize_ip,
    pack_compact_peer,
    resolve_peer_ipv4,
    resolve_peer_ipv6,
)
from app.torrent.magnet import decode_peer_id
from app.torrent.store import TorrentSessionStore

logger = logging.getLogger(__name__)

BEP15_PROTOCOL_ID = 0x41727101980
ACTION_CONNECT = 0
ACTION_ANNOUNCE = 1
ACTION_SCRAPE = 2
ACTION_ERROR = 3


class _UDPTrackerProtocol(asyncio.DatagramProtocol):
    """Asyncio datagram protocol implementing BEP 15 connect, announce, and scrape."""

    def __init__(
        self,
        store: TorrentSessionStore,
        *,
        peer_port_getter: Callable[[], int | None] | None = None,
        peer_prober: Callable[[str, str, int], Any] | None = None,
        public_ipv4: str | None = None,
        public_ipv6: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._peer_port_getter = peer_port_getter
        self._peer_prober = peer_prober
        self._public_ipv4 = public_ipv4
        self._public_ipv6 = public_ipv6
        self._clock = clock
        self._secret = secrets.token_bytes(32)
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        if self._transport is None or len(data) < 16:
            return

        client_ip = normalize_ip(str(addr[0])) or str(addr[0])
        remote_port = int(addr[1])

        first_qword, action, tx_id = struct.unpack("!QII", data[:16])

        if action == ACTION_CONNECT:
            if first_qword != BEP15_PROTOCOL_ID:
                return
            conn_id = self._make_connection_id(client_ip, self._minute_bucket())
            self._transport.sendto(struct.pack("!IIQ", ACTION_CONNECT, tx_id, conn_id), addr)
            return

        if not self._verify_connection_id(client_ip, first_qword):
            self._send_error(tx_id, "Invalid or expired connection_id", addr)
            return

        if action == ACTION_ANNOUNCE:
            self._handle_announce(data, tx_id, client_ip, remote_port, addr)
        elif action == ACTION_SCRAPE:
            self._handle_scrape(data, tx_id, client_ip, remote_port, addr)
        else:
            self._send_error(tx_id, "Unsupported action", addr)

    def _handle_announce(
        self,
        data: bytes,
        tx_id: int,
        client_ip: str,
        remote_port: int,
        addr: tuple[Any, ...],
    ) -> None:
        assert self._transport is not None
        if len(data) < 98:
            self._send_error(tx_id, "Malformed announce packet", addr)
            return

        info_hash_hex = data[16:36].hex()
        peer_id = data[36:56]
        ip_uint32, _key, num_want, announced_port = struct.unpack("!IIiH", data[84:98])

        reported_ips: list[str] = []
        if ip_uint32 != 0:
            reported_ips.append(socket.inet_ntoa(struct.pack("!I", ip_uint32)))

        matched = self._store.record_hit(
            ip=client_ip,
            port=announced_port or remote_port,
            source="udp_tracker",
            info_hash=info_hash_hex,
            client=decode_peer_id(peer_id),
            reported_ips=reported_ips,
        )
        if matched is not None and self._peer_prober and 1 <= announced_port <= 65535:
            self._peer_prober(info_hash_hex, client_ip, announced_port)

        peers_payload = b""
        peer_port = self._peer_port_getter() if self._peer_port_getter else None
        if peer_port and num_want != 0:
            peers_payload = self._compact_peers_for_client(client_ip, peer_port)

        header = struct.pack("!IIIII", ACTION_ANNOUNCE, tx_id, 60, 0, 1)
        self._transport.sendto(header + peers_payload, addr)

    def _handle_scrape(
        self,
        data: bytes,
        tx_id: int,
        client_ip: str,
        remote_port: int,
        addr: tuple[Any, ...],
    ) -> None:
        assert self._transport is not None
        body = data[16:]
        count = min(len(body) // 20, 74)
        for idx in range(count):
            info_hash_hex = body[idx * 20 : (idx + 1) * 20].hex()
            self._store.record_hit(
                ip=client_ip,
                port=remote_port,
                source="udp_scrape",
                info_hash=info_hash_hex,
            )

        resp = struct.pack("!II", ACTION_SCRAPE, tx_id) + (struct.pack("!III", 1, 0, 0) * count)
        self._transport.sendto(resp, addr)

    def _compact_peers_for_client(self, client_ip: str, peer_port: int) -> bytes:
        """Return compact peers in the same address family as the UDP client."""
        if ":" in client_ip:
            fallback = "::1" if client_ip == "::1" else None
            peer_ip = resolve_peer_ipv6(fallback, self._public_ipv6)
        else:
            fallback = "127.0.0.1" if client_ip == "127.0.0.1" else None
            peer_ip = resolve_peer_ipv4(fallback, self._public_ipv4)
        if peer_ip is None:
            return b""
        return pack_compact_peer(peer_ip, peer_port)

    def _send_error(self, tx_id: int, message: str, addr: tuple[Any, ...]) -> None:
        if self._transport is not None:
            payload = struct.pack("!II", ACTION_ERROR, tx_id) + message.encode() + b"\x00"
            self._transport.sendto(payload, addr)

    def _minute_bucket(self) -> int:
        return int(self._clock() // 60)

    def _make_connection_id(self, client_ip: str, bucket: int) -> int:
        digest = hmac.new(
            self._secret,
            f"{client_ip}:{bucket}".encode(),
            hashlib.sha256,
        ).digest()
        return struct.unpack("!Q", digest[:8])[0]

    def _verify_connection_id(self, client_ip: str, conn_id: int) -> bool:
        now_bucket = self._minute_bucket()
        return any(
            hmac.compare_digest(
                struct.pack("!Q", conn_id),
                struct.pack("!Q", self._make_connection_id(client_ip, now_bucket - offset)),
            )
            for offset in (0, 1, 2)
        )


class UDPTrackerServer:
    """Manages lifecycle of the asyncio UDP BitTorrent tracker endpoint."""

    def __init__(
        self,
        store: TorrentSessionStore,
        *,
        host: str = "::",
        port: int = 6969,
        strict_ports: bool = False,
        peer_port_getter: Callable[[], int | None] | None = None,
        peer_prober: Callable[[str, str, int], Any] | None = None,
        public_ipv4: str | None = None,
        public_ipv6: str | None = None,
    ) -> None:
        self.store = store
        self.host = host
        self.configured_port = port
        self.strict_ports = strict_ports
        self._peer_port_getter = peer_port_getter
        self._peer_prober = peer_prober
        self._public_ipv4 = public_ipv4
        self._public_ipv6 = public_ipv6
        self._transport: asyncio.DatagramTransport | None = None
        self.bound_port: int | None = None

    async def start(self) -> int:
        loop = asyncio.get_running_loop()
        protocol_factory = lambda: _UDPTrackerProtocol(
            self.store,
            peer_port_getter=self._peer_port_getter,
            peer_prober=self._peer_prober,
            public_ipv4=self._public_ipv4,
            public_ipv6=self._public_ipv6,
        )
        try:
            sock = bind_listener_socket(self.host, self.configured_port, socket.SOCK_DGRAM)
        except OSError as exc:
            if self.strict_ports or self.configured_port == 0:
                raise
            logger.warning(
                "UDP port %d unavailable (%s); falling back to ephemeral UDP port",
                self.configured_port,
                exc,
            )
            sock = bind_listener_socket(self.host, 0, socket.SOCK_DGRAM)

        transport, _ = await loop.create_datagram_endpoint(protocol_factory, sock=sock)
        self._transport = transport  # type: ignore[assignment]
        sockname = transport.get_extra_info("sockname")
        self.bound_port = int(sockname[1])
        logger.info("UDP BitTorrent tracker listening on [%s]:%d", self.host, self.bound_port)
        return self.bound_port

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            self.bound_port = None
