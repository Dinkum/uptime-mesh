from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.schemas.discovery import DiscoveryServiceOut
from app.services import discovery as discovery_service

router = APIRouter(prefix="/discovery", tags=["discovery"])


@router.get("/services", response_model=list[DiscoveryServiceOut])
async def list_discovery_services(
    session: AsyncSession = Depends(get_db_session),
) -> list[DiscoveryServiceOut]:
    settings = get_settings()
    return await discovery_service.list_discovery_services(
        session,
        domain=settings.runtime_discovery_domain,
    )


@router.get("/dns/zone", response_class=PlainTextResponse)
async def render_dns_zone(
    session: AsyncSession = Depends(get_db_session),
) -> PlainTextResponse:
    settings = get_settings()
    zone, _, _ = await discovery_service.render_zone_file(
        session,
        domain=settings.runtime_discovery_domain,
        ttl_seconds=settings.runtime_discovery_ttl_seconds,
    )
    return PlainTextResponse(zone, media_type="text/plain; charset=utf-8")

