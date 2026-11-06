"""Minimal endpoint returning the HTTP client's observed IP address."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.config import Settings
from app.ip_utils import classify_ip, extract_client_ip

router = APIRouter(tags=["ip"])


@router.get("/api/ip")
async def get_client_ip(request: Request) -> JSONResponse:
    """Return the IP address and connection details used to reach this server."""
    settings: Settings = request.app.state.settings
    raw_ip, detected_via = extract_client_ip(
        request,
        trust_proxy_headers=settings.trust_proxy_headers,
    )
    info = classify_ip(raw_ip)

    return JSONResponse(
        content={
            "ip": info.ip,
            "version": info.version,
            "scope": info.scope,
            "is_public": info.is_public,
            "detected_via": detected_via,
            "user_agent": request.headers.get("user-agent", ""),
        },
        headers={"Cache-Control": "no-store"},
    )

