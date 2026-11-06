"""FastAPI application entrypoint and background BitTorrent listener lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings, load_settings
from app.routes.ip import router as ip_router
from app.routes.torrent import router as torrent_router
from app.torrent.peer_server import PeerWireServer
from app.torrent.store import TorrentSessionStore
from app.torrent.udp_tracker import UDPTrackerServer

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(
    settings: Settings | None = None,
    store: TorrentSessionStore | None = None,
) -> FastAPI:
    """Construct and wire the FastAPI application."""
    cfg = settings or load_settings()
    session_store = store or TorrentSessionStore(
        ttl_seconds=cfg.session_ttl_seconds,
        max_sessions=cfg.max_sessions,
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        peer_srv: PeerWireServer | None = None
        udp_srv: UDPTrackerServer | None = None

        if cfg.peer_server_enabled:
            peer_srv = PeerWireServer(
                session_store,
                host=cfg.bind_host,
                port=cfg.peer_server_port,
                strict_ports=cfg.strict_ports,
            )
            await peer_srv.start()

        if cfg.udp_tracker_enabled:
            udp_srv = UDPTrackerServer(
                session_store,
                host=cfg.bind_host,
                port=cfg.udp_tracker_port,
                strict_ports=cfg.strict_ports,
                peer_port_getter=lambda: peer_srv.bound_port if peer_srv else None,
                public_ipv4=cfg.public_ipv4,
            )
            await udp_srv.start()

        application.state.peer_server = peer_srv
        application.state.udp_server = udp_srv
        try:
            yield
        finally:
            if udp_srv is not None:
                await udp_srv.stop()
            if peer_srv is not None:
                await peer_srv.stop()
            application.state.udp_server = None
            application.state.peer_server = None

    application = FastAPI(
        title="IP Leak Check Service",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.settings = cfg
    application.state.store = session_store
    application.state.udp_server = None
    application.state.peer_server = None

    application.include_router(ip_router)
    application.include_router(torrent_router)

    @application.get("/", include_in_schema=False)
    async def index_page() -> FileResponse:
        return FileResponse(
            STATIC_DIR / "index.html",
            headers={"Cache-Control": "no-cache"},
        )

    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return application


app = create_app()

