"""In-memory store for active BitTorrent leak-check sessions and observed connections."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from app.ip_utils import classify_ip, normalize_ip
from app.torrent.magnet import build_magnet_uri, build_torrent_file

DetectionSource = Literal[
    "http_tracker",
    "udp_tracker",
    "bt_peer",
    "bt_peer_outbound",
    "http_scrape",
    "udp_scrape",
]

ProbeStatus = Literal["pending", "open", "closed"]

_UNSPECIFIED_IPS = {"0.0.0.0", "::"}


@dataclass(slots=True)
class Detection:
    """A single (deduplicated per IP + protocol source) BitTorrent connection observation."""

    ip: str
    ip_version: int | None
    ip_scope: str
    is_public: bool
    port: int | None
    source: DetectionSource
    client: str
    reported_ips: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    hit_count: int = 1

    def to_dict(self, *, creator_ip: str) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "ip_version": self.ip_version,
            "ip_scope": self.ip_scope,
            "is_public": self.is_public,
            "port": self.port,
            "source": self.source,
            "client": self.client,
            "reported_ips": list(self.reported_ips),
            "matches_browser_ip": self.ip == creator_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
        }


@dataclass(slots=True)
class TorrentSession:
    """Represents one generated magnet/.torrent test session."""

    token: str
    info_hash: str
    display_name: str
    magnet_uri: str
    torrent_bytes: bytes
    trackers: list[str]
    peers: list[str]
    creator_ip: str
    created_at: float
    expires_at: float
    detections: list[Detection] = field(default_factory=list)
    peer_probes: dict[str, ProbeStatus] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        unique_ips: list[str] = []
        reported_mismatch_ips: list[str] = []

        for det in self.detections:
            if det.ip not in unique_ips:
                unique_ips.append(det.ip)
            for rep_ip in det.reported_ips:
                if rep_ip != det.ip and rep_ip not in reported_mismatch_ips:
                    reported_mismatch_ips.append(rep_ip)

        all_observed = list(dict.fromkeys([*unique_ips, *reported_mismatch_ips]))
        if not all_observed:
            matches_browser_ip: bool | None = None
        else:
            matches_browser_ip = all(ip == self.creator_ip for ip in all_observed)

        return {
            "token": self.token,
            "info_hash": self.info_hash,
            "display_name": self.display_name,
            "magnet_uri": self.magnet_uri,
            "torrent_url": f"/api/torrent/sessions/{self.token}/torrent",
            "trackers": list(self.trackers),
            "peers": list(self.peers),
            "creator_ip": self.creator_ip,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "detections": [d.to_dict(creator_ip=self.creator_ip) for d in self.detections],
            "peer_probes": dict(self.peer_probes),
            "summary": {
                "total_detections": len(self.detections),
                "unique_ips": unique_ips,
                "reported_mismatch_ips": reported_mismatch_ips,
                "matches_browser_ip": matches_browser_ip,
                "has_multi_ip_leak": len(all_observed) > 1,
            },
        }


class TorrentSessionStore:
    """Bounded, TTL-expiring in-memory registry of active BitTorrent leak test sessions."""

    def __init__(
        self,
        *,
        ttl_seconds: int = 900,
        max_sessions: int = 1000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._clock = clock
        self._by_token: dict[str, TorrentSession] = {}
        self._by_info_hash: dict[str, TorrentSession] = {}

    def purge_expired(self) -> int:
        """Remove expired sessions and return the count removed."""
        now = self._clock()
        expired_tokens = [
            token for token, session in self._by_token.items() if now >= session.expires_at
        ]
        for token in expired_tokens:
            self._remove_token(token)
        return len(expired_tokens)

    def _remove_token(self, token: str) -> None:
        session = self._by_token.pop(token, None)
        if session is not None:
            self._by_info_hash.pop(session.info_hash, None)

    def create_session(
        self,
        *,
        creator_ip: str,
        trackers: list[str],
        peers: list[str] | None = None,
        token: str | None = None,
    ) -> TorrentSession:
        """Create and register a new magnet/.torrent test session."""
        self.purge_expired()

        while len(self._by_token) >= self.max_sessions and self._by_token:
            oldest_token = next(iter(self._by_token))
            self._remove_token(oldest_token)

        session_token = token or secrets.token_hex(8)
        display_name = f"ipleak-check-{session_token[:8]}"
        peer_list = list(peers or [])
        info_hash, torrent_bytes = build_torrent_file(
            display_name=display_name,
            trackers=trackers,
        )
        magnet_uri = build_magnet_uri(
            info_hash,
            display_name=display_name,
            trackers=trackers,
            peers=peer_list,
        )

        now = self._clock()
        normalized_creator = normalize_ip(creator_ip) or creator_ip
        session = TorrentSession(
            token=session_token,
            info_hash=info_hash,
            display_name=display_name,
            magnet_uri=magnet_uri,
            torrent_bytes=torrent_bytes,
            trackers=list(trackers),
            peers=peer_list,
            creator_ip=normalized_creator,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._by_token[session_token] = session
        self._by_info_hash[info_hash] = session
        return session

    def get_by_token(self, token: str) -> TorrentSession | None:
        self.purge_expired()
        return self._by_token.get(token)

    def get_by_info_hash(self, info_hash: str) -> TorrentSession | None:
        self.purge_expired()
        return self._by_info_hash.get(info_hash.strip().lower())

    def claim_peer_probe(self, info_hash: str, endpoint: str) -> bool:
        """Mark ``endpoint`` ('ip:port') as pending outbound probe if not yet probed."""
        session = self.get_by_info_hash(info_hash)
        if session is None or endpoint in session.peer_probes:
            return False
        session.peer_probes[endpoint] = "pending"
        return True

    def update_peer_probe(self, info_hash: str, endpoint: str, status: ProbeStatus) -> None:
        """Update the result ('open' or 'closed') of an outbound peer connection probe."""
        session = self.get_by_info_hash(info_hash)
        if session is not None:
            session.peer_probes[endpoint] = status

    def record_hit(
        self,
        *,
        ip: str,
        source: DetectionSource,
        info_hash: str | None = None,
        token: str | None = None,
        port: int | None = None,
        client: str = "Unknown BitTorrent Client",
        reported_ips: list[str] | None = None,
    ) -> TorrentSession | None:
        """Record an incoming or outbound tracker/peer connection against its session."""
        self.purge_expired()

        session: TorrentSession | None = None
        if info_hash:
            normalized_hash = info_hash.strip().lower()
            session = self._by_info_hash.get(normalized_hash)
            if session is not None and token and session.token != token:
                return None
        elif token:
            session = self._by_token.get(token)

        if session is None:
            return None

        ip_info = classify_ip(ip)
        clean_reported: list[str] = []
        for raw_rep in reported_ips or []:
            norm_rep = normalize_ip(raw_rep)
            if norm_rep and norm_rep not in _UNSPECIFIED_IPS and norm_rep not in clean_reported:
                clean_reported.append(norm_rep)

        now = self._clock()
        for existing in session.detections:
            if existing.ip == ip_info.ip and existing.source == source:
                existing.hit_count += 1
                existing.last_seen = now
                if port:
                    existing.port = port
                if existing.client == "Unknown BitTorrent Client" and client != existing.client:
                    existing.client = client
                for rep in clean_reported:
                    if rep not in existing.reported_ips:
                        existing.reported_ips.append(rep)
                return session

        session.detections.append(
            Detection(
                ip=ip_info.ip,
                ip_version=ip_info.version,
                ip_scope=ip_info.scope,
                is_public=ip_info.is_public,
                port=port,
                source=source,
                client=client,
                reported_ips=clean_reported,
                first_seen=now,
                last_seen=now,
                hit_count=1,
            )
        )
        return session
