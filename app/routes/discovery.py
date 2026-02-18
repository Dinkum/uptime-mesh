from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.schemas.discovery import DiscoveryServiceOut, DiscoveryStatusOut
from app.services import cluster_settings as cluster_settings_service
from app.services import discovery as discovery_service

router = APIRouter(prefix="/discovery", tags=["discovery"])


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


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


@router.get("/dns/corefile", response_class=PlainTextResponse)
async def render_dns_corefile() -> PlainTextResponse:
    settings = get_settings()
    corefile = discovery_service.render_corefile(
        domain=settings.runtime_discovery_domain,
        zone_file_path=settings.runtime_discovery_zone_path,
        listen=settings.runtime_discovery_listen,
        forwarders=settings.runtime_discovery_forwarders,
    )
    return PlainTextResponse(corefile, media_type="text/plain; charset=utf-8")


@router.get("/status", response_model=DiscoveryStatusOut)
async def discovery_status(
    session: AsyncSession = Depends(get_db_session),
) -> DiscoveryStatusOut:
    settings = get_settings()
    settings_map = await cluster_settings_service.get_settings_map(session)
    zone_path = Path(settings.runtime_discovery_zone_path)
    corefile_path = Path(settings.runtime_discovery_corefile_path)
    return DiscoveryStatusOut(
        domain=settings.runtime_discovery_domain,
        ttl_seconds=settings.runtime_discovery_ttl_seconds,
        zone_path=str(zone_path),
        corefile_path=str(corefile_path),
        zone_exists=zone_path.exists(),
        corefile_exists=corefile_path.exists(),
        zone_sha256=settings_map.get("discovery_zone_sha256", ""),
        corefile_sha256=settings_map.get("discovery_corefile_sha256", ""),
        service_count=_safe_int(settings_map.get("discovery_service_count", "0")),
        endpoint_count=_safe_int(settings_map.get("discovery_endpoint_count", "0")),
        last_sync_at=settings_map.get("discovery_last_sync_at", ""),
    )
