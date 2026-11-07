"""Routes for magnet session generation and HTTP BitTorrent tracker/scrape callbacks."""

from __future__ import annotations

import secrets
import socket
import struct
import urllib.parse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from app.config import Settings
from app.ip_utils import extract_client_ip, resolve_peer_ipv4
from app.torrent.bencode import bencode
from app.torrent.magnet import decode_peer_id, format_host_port
from app.torrent.peer_server import PeerWireServer
from app.torrent.store import TorrentSessionStore
from app.torrent.udp_tracker import UDPTrackerServer

router = APIRouter(tags=["torrent"])

_SERVER_PEER_ID = b"-IL0100-000000000000"


@router.post("/api/torrent/sessions", status_code=201)
async def create_torrent_session(request: Request) -> JSONResponse:
    """Generate a unique magnet link session and return its tracking details."""
    settings: Settings = request.app.state.settings
    store: TorrentSessionStore = request.app.state.store
    udp_server: UDPTrackerServer | None = request.app.state.udp_server
    peer_server: PeerWireServer | None = request.app.state.peer_server

    creator_ip, _ = extract_client_ip(
        request,
        trust_proxy_headers=settings.trust_proxy_headers,
    )

    token = secrets.token_hex(8)
    tracker_host = _determine_tracker_host(request, settings)
    http_base = _determine_http_base_url(request, settings, tracker_host)

    trackers = [f"{http_base}/announce/{token}"]
    if udp_server and udp_server.bound_port:
        trackers.append(f"udp://{format_host_port(tracker_host, udp_server.bound_port)}/announce")

    peers: list[str] = []
    if peer_server and peer_server.bound_port:
        peers.append(format_host_port(tracker_host, peer_server.bound_port))

    session = store.create_session(
        creator_ip=creator_ip,
        trackers=trackers,
        peers=peers,
        token=token,
    )

    return JSONResponse(
        status_code=201,
        content=session.to_dict(),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/api/torrent/sessions/{token}")
async def get_torrent_session(token: str, request: Request) -> JSONResponse:
    """Fetch observed BitTorrent client connections for an active session."""
    store: TorrentSessionStore = request.app.state.store
    session = store.get_by_token(token)
    if session is None:
        raise HTTPException(status_code=404, detail="Torrent check session not found or expired")

    return JSONResponse(
        content=session.to_dict(),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/api/torrent/sessions/{token}/torrent")
async def download_torrent_file(token: str, request: Request) -> Response:
    """Download a valid .torrent metainfo file matching the session's magnet info_hash."""
    store: TorrentSessionStore = request.app.state.store
    session = store.get_by_token(token)
    if session is None:
        raise HTTPException(status_code=404, detail="Torrent check session not found or expired")

    return Response(
        content=session.torrent_bytes,
        media_type="application/x-bittorrent",
        headers={
            "Content-Disposition": f'attachment; filename="{session.display_name}.torrent"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/announce")
@router.get("/announce/{token}")
async def http_tracker_announce(request: Request, token: str | None = None) -> Response:
    """BEP 3 / BEP 23 HTTP BitTorrent tracker announce endpoint."""
    settings: Settings = request.app.state.settings
    store: TorrentSessionStore = request.app.state.store
    peer_server: PeerWireServer | None = request.app.state.peer_server

    params = _parse_binary_query(request)
    info_hash_bytes = _extract_info_hash_bytes(params.get("info_hash"))
    if info_hash_bytes is None:
        return _bencoded_response({"failure reason": "Missing or invalid 20-byte info_hash"})

    raw_peer_ids = params.get("peer_id")
    peer_id_bytes = raw_peer_ids[0].encode("latin-1") if raw_peer_ids else None

    announced_port = _parse_optional_int(params.get("port"))
    numwant = _parse_optional_int(params.get("numwant"), default=50)
    compact = (params.get("compact") or ["1"])[0] != "0"

    reported_ips: list[str] = []
    for key in ("ip", "ipv4", "ipv6"):
        for val in params.get(key, []):
            if val:
                reported_ips.append(val)

    client_ip, _ = extract_client_ip(
        request,
        trust_proxy_headers=settings.trust_proxy_headers,
    )
    client_label = decode_peer_id(peer_id_bytes, request.headers.get("user-agent"))

    session = store.record_hit(
        ip=client_ip,
        port=announced_port,
        source="http_tracker",
        info_hash=info_hash_bytes.hex(),
        token=token,
        client=client_label,
        reported_ips=reported_ips,
    )
    if session is None:
        return _bencoded_response({"failure reason": "Unknown or expired torrent session"})

    if peer_server is not None and announced_port:
        peer_server.schedule_outbound_probe(session.info_hash, client_ip, announced_port)

    peer_port = peer_server.bound_port if peer_server else None
    peer_ipv4 = (
        resolve_peer_ipv4(request.url.hostname, settings.public_ipv4)
        if peer_port and numwant != 0
        else None
    )

    if compact:
        peers_blob = (
            socket.inet_aton(peer_ipv4) + struct.pack("!H", peer_port)
            if (peer_ipv4 and peer_port)
            else b""
        )
        return _bencoded_response(
            {
                "interval": 60,
                "min interval": 30,
                "complete": 1,
                "incomplete": 0,
                "peers": peers_blob,
                "peers6": b"",
            }
        )

    peers_list = (
        [{"peer id": _SERVER_PEER_ID, "ip": peer_ipv4, "port": peer_port}]
        if (peer_ipv4 and peer_port)
        else []
    )
    return _bencoded_response(
        {
            "interval": 60,
            "min interval": 30,
            "complete": 1,
            "incomplete": 0,
            "peers": peers_list,
        }
    )


@router.get("/scrape")
@router.get("/scrape/{token}")
async def http_tracker_scrape(request: Request, token: str | None = None) -> Response:
    """BEP 48 HTTP BitTorrent tracker scrape endpoint."""
    settings: Settings = request.app.state.settings
    store: TorrentSessionStore = request.app.state.store

    params = _parse_binary_query(request)
    client_ip, _ = extract_client_ip(
        request,
        trust_proxy_headers=settings.trust_proxy_headers,
    )
    client_label = decode_peer_id(None, request.headers.get("user-agent"))

    files: dict[bytes, dict[str, int]] = {}
    raw_hashes = params.get("info_hash", [])
    if raw_hashes:
        for raw_val in raw_hashes:
            ih_bytes = _extract_info_hash_bytes([raw_val])
            if ih_bytes is not None:
                matched = store.record_hit(
                    ip=client_ip,
                    source="http_scrape",
                    info_hash=ih_bytes.hex(),
                    token=token,
                    client=client_label,
                )
                if matched is not None:
                    files[ih_bytes] = {"complete": 1, "downloaded": 0, "incomplete": 0}
    elif token:
        matched = store.record_hit(
            ip=client_ip,
            source="http_scrape",
            token=token,
            client=client_label,
        )
        if matched is not None:
            files[bytes.fromhex(matched.info_hash)] = {
                "complete": 1,
                "downloaded": 0,
                "incomplete": 0,
            }

    return _bencoded_response({"files": files})


def _parse_binary_query(request: Request) -> dict[str, list[str]]:
    """Parse URL query string with latin-1 so arbitrary 20-byte hashes stay lossless."""
    raw_qs = request.scope.get("query_string", b"").decode("latin-1")
    if not raw_qs:
        return {}
    return urllib.parse.parse_qs(
        raw_qs,
        keep_blank_values=True,
        encoding="latin-1",
        errors="strict",
    )


def _extract_info_hash_bytes(values: list[str] | None) -> bytes | None:
    if not values:
        return None
    raw = values[0].encode("latin-1")
    if len(raw) == 20:
        return raw
    if len(raw) == 40:
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except ValueError:
            return None
    return None


def _parse_optional_int(values: list[str] | None, default: int | None = None) -> int | None:
    if not values or not values[0]:
        return default
    try:
        return int(values[0])
    except ValueError:
        return default


def _determine_tracker_host(request: Request, settings: Settings) -> str:
    if settings.public_host:
        return settings.public_host
    req_host = request.url.hostname or "127.0.0.1"
    # On Windows/dual-stack systems, 'localhost' often resolves to ::1 first;
    # normalizing to 127.0.0.1 ensures local UDP/TCP torrent listeners bound on 0.0.0.0 match.
    if req_host == "localhost":
        return "127.0.0.1"
    return req_host


def _determine_http_base_url(request: Request, settings: Settings, tracker_host: str) -> str:
    if settings.public_http_base_url:
        return settings.public_http_base_url.rstrip("/")

    scheme = request.url.scheme or "http"
    port = request.url.port
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        host_part = format_host_port(tracker_host, port)
    elif ":" in tracker_host and not tracker_host.startswith("["):
        host_part = f"[{tracker_host}]"
    else:
        host_part = tracker_host
    return f"{scheme}://{host_part}"


def _bencoded_response(payload: dict) -> Response:
    return Response(
        content=bencode(payload),
        media_type="text/plain",
        headers={"Cache-Control": "no-store"},
    )

