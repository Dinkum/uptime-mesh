from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.schemas.gateway import GatewayRouteOut, GatewayStatusOut
from app.services import cluster_settings as cluster_settings_service
from app.services import gateway as gateway_service

router = APIRouter(prefix="/gateway", tags=["gateway"])


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


@router.get("/routes", response_model=list[GatewayRouteOut])
async def list_gateway_routes(
    session: AsyncSession = Depends(get_db_session),
) -> list[GatewayRouteOut]:
    return await gateway_service.list_gateway_routes(session)


@router.get("/nginx/config", response_class=PlainTextResponse)
async def render_gateway_config(
    session: AsyncSession = Depends(get_db_session),
) -> PlainTextResponse:
    settings = get_settings()
    rendered = await gateway_service.render_gateway_config(
        session,
        listen=settings.runtime_gateway_listen,
        default_server_name=settings.runtime_gateway_server_name,
    )
    return PlainTextResponse(rendered.config, media_type="text/plain; charset=utf-8")


@router.get("/status", response_model=GatewayStatusOut)
async def gateway_status(
    session: AsyncSession = Depends(get_db_session),
) -> GatewayStatusOut:
    settings = get_settings()
    settings_map = await cluster_settings_service.get_settings_map(session)
    config_path, candidate_path, backup_path = gateway_service.resolve_gateway_paths(
        config_path=settings.runtime_gateway_config_path,
        candidate_path=settings.runtime_gateway_candidate_path,
        backup_path=settings.runtime_gateway_backup_path,
    )
    healthcheck_urls = [
        item.strip()
        for item in settings.runtime_gateway_healthcheck_urls.split(",")
        if item.strip()
    ]
    return GatewayStatusOut(
        enabled=settings.runtime_gateway_enable,
        config_path=str(config_path),
        candidate_path=str(candidate_path),
        backup_path=str(backup_path),
        listen=settings.runtime_gateway_listen,
        server_name=settings.runtime_gateway_server_name,
        routes=_safe_int(settings_map.get("gateway_route_count", "0")),
        upstreams=_safe_int(settings_map.get("gateway_upstream_count", "0")),
        last_sync_at=settings_map.get("gateway_last_sync_at", ""),
        last_apply_status=settings_map.get("gateway_last_apply_status", "unknown"),
        last_apply_error=settings_map.get("gateway_last_apply_error", ""),
        healthcheck_urls=healthcheck_urls,
    )
