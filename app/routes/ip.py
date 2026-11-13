"""Minimal endpoint returning the HTTP client's observed IP address."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import Settings
from app.ip_utils import classify_ip, describe_address, extract_client_ip

router = APIRouter(tags=["ip"])

_MAX_CLASSIFY_ADDRESSES = 64
_MAX_ADDRESS_CHARS = 128


class ClassifyRequest(BaseModel):
    addresses: list[str]


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


@router.post("/api/ip/classify")
async def classify_addresses(body: ClassifyRequest) -> JSONResponse:
    """Classify ICE candidate addresses with the same rules as the HTTP IP endpoint."""
    if len(body.addresses) > _MAX_CLASSIFY_ADDRESSES:
        raise HTTPException(
            status_code=422,
            detail=f"At most {_MAX_CLASSIFY_ADDRESSES} addresses can be classified at once",
        )
    if any(len(item) > _MAX_ADDRESS_CHARS for item in body.addresses):
        raise HTTPException(status_code=422, detail="Address is too long")

    return JSONResponse(
        content={"results": [describe_address(raw).to_dict() for raw in body.addresses]},
        headers={"Cache-Control": "no-store"},
    )

