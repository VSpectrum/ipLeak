"""Magnet URI builder (BEP 9), .torrent builder (BEP 3/12), and peer_id client decoder."""

from __future__ import annotations

import hashlib
import re
import secrets
import urllib.parse
from typing import Any

from app.torrent.bencode import bencode

_AZUREUS_CLIENTS: dict[str, str] = {
    "qB": "qBittorrent",
    "TR": "Transmission",
    "DE": "Deluge",
    "UT": "µTorrent",
    "uT": "µTorrent",
    "UM": "µTorrent Mac",
    "LT": "libtorrent",
    "lt": "rTorrent (libtorrent)",
    "AZ": "Vuze / Azureus",
    "BT": "BitTorrent",
    "A2": "aria2",
    "KT": "KTorrent",
    "BI": "BiglyBT",
    "FW": "FrostWire",
    "WW": "WebTorrent",
    "WD": "WebTorrent Desktop",
    "PI": "PicoTorrent",
    "FD": "Free Download Manager",
    "TIX": "Tixati",
}

_MAINLINE_RE = re.compile(r"^M(\d+-\d+(?:-\d+)?)--")

# 16-byte placeholder payload. ``pieces`` is the SHA-1 of this content so strict
# clients accept the metainfo instead of rejecting an all-zero piece hash.
TORRENT_PAYLOAD = b"ipleak-check!!!!"


def format_host_port(host: str, port: int) -> str:
    """Format host and port, bracketing bare IPv6 literals."""
    cleaned = host.strip()
    if ":" in cleaned and not (cleaned.startswith("[") and cleaned.endswith("]")):
        return f"[{cleaned}]:{port}"
    return f"{cleaned}:{port}"


def build_magnet_uri(
    info_hash: str,
    *,
    display_name: str,
    trackers: list[str],
    peers: list[str] | None = None,
) -> str:
    """Build a BEP 9 magnet URI with tracker (`tr`) and direct peer (`x.pe`) hints."""
    normalized_hash = info_hash.strip().lower()
    if len(normalized_hash) != 40:
        raise ValueError("info_hash must be a 40-character SHA-1 hex digest")
    try:
        bytes.fromhex(normalized_hash)
    except ValueError as exc:
        raise ValueError("info_hash must contain valid hexadecimal characters") from exc

    parts = [
        f"xt=urn:btih:{normalized_hash}",
        f"dn={urllib.parse.quote(display_name, safe='')}",
    ]
    for tracker in trackers:
        parts.append(f"tr={urllib.parse.quote(tracker, safe='')}")

    for peer in peers or []:
        # BEP 9 expects host:port (or [ipv6]:port) with unescaped colons/brackets
        parts.append(f"x.pe={urllib.parse.quote(peer, safe=':[]')}")

    return "magnet:?" + "&".join(parts)


def build_torrent_file(
    *,
    display_name: str,
    trackers: list[str],
    nonce: str | None = None,
) -> tuple[str, bytes]:
    """Build a minimal valid BEP 3 / BEP 12 .torrent file and return ``(info_hash_hex, bytes)``."""
    info_dict: dict[str, Any] = {
        "length": len(TORRENT_PAYLOAD),
        "name": display_name,
        "nonce": nonce or secrets.token_hex(8),
        "piece length": 16384,
        "pieces": hashlib.sha1(TORRENT_PAYLOAD).digest(),
    }
    info_hash = hashlib.sha1(bencode(info_dict)).hexdigest()

    metainfo: dict[str, Any] = {
        "created by": "ipleak-service",
        "info": info_dict,
    }
    if trackers:
        metainfo["announce"] = trackers[0]
        metainfo["announce-list"] = [[tr] for tr in trackers]

    return info_hash, bencode(metainfo)


def decode_peer_id(peer_id: bytes | None, user_agent: str | None = None) -> str:
    """Identify the BitTorrent client from HTTP User-Agent or 20-byte peer_id."""
    if user_agent:
        cleaned_ua = "".join(ch for ch in user_agent.strip() if 32 <= ord(ch) < 127)[:80]
        if cleaned_ua:
            return cleaned_ua

    if not peer_id or len(peer_id) < 8:
        return "Unknown BitTorrent Client"

    # Azureus style: -XXYYYY-xxxxxxxxxxxx
    if peer_id[0:1] == b"-" and peer_id[7:8] == b"-":
        code = peer_id[1:3].decode("latin-1")
        ver_raw = peer_id[3:7].decode("latin-1")
        client_name = _AZUREUS_CLIENTS.get(code, f"Client ({code})")
        version = _format_azureus_version(ver_raw)
        return f"{client_name} {version}".strip()

    # Mainline style: M4-3-6--xxxxxxxxxxxx
    prefix = peer_id[:12].decode("latin-1")
    match = _MAINLINE_RE.match(prefix)
    if match:
        return f"BitTorrent {match.group(1).replace('-', '.')}"

    if peer_id.startswith(b"TIX") and len(peer_id) >= 7:
        ver = peer_id[3:7].decode("latin-1")
        return f"Tixati {_format_azureus_version(ver)}".strip()

    return "Unknown BitTorrent Client"


def _format_azureus_version(raw: str) -> str:
    """Turn a 4-char Azureus version tag like '4650' into '4.6.5'."""
    chars = [ch for ch in raw if ch.isalnum()]
    if not chars:
        return ""
    # Strip trailing '0' padding common in 4-digit tags like 4650 -> 4.6.5
    while len(chars) > 2 and chars[-1] == "0":
        chars.pop()
    if all(ch.isdigit() for ch in chars):
        return ".".join(chars)
    # Handle hex/letter suffixes like 211s -> 2.1.1s
    digits = [ch for ch in chars if ch.isdigit()]
    suffix = "".join(ch for ch in chars if not ch.isdigit())
    if digits:
        return ".".join(digits) + suffix
    return "".join(chars)
