from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.schemas.monitoring import MonitoringStatusOut
from app.services import cluster_settings as cluster_settings_service
from app.services import monitoring as monitoring_service

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


def _split_csv(raw: str) -> list[str]:
    values: list[str] = []
    for item in raw.split(","):
        clean = item.strip()
        if clean:
            values.append(clean)
    return values


@router.get("/prometheus/config", response_class=PlainTextResponse)
async def render_prometheus_config(
    session: AsyncSession = Depends(get_db_session),
) -> PlainTextResponse:
    settings = get_settings()
    rendered = await monitoring_service.render_prometheus_config(
        session,
        app_metrics_path="/metrics",
        default_api_port=settings.server_port,
        node_exporter_port=settings.runtime_monitoring_node_exporter_port,
        scrape_interval_seconds=settings.runtime_monitoring_scrape_interval_seconds,
        evaluation_interval_seconds=settings.runtime_monitoring_evaluation_interval_seconds,
        rules_path=settings.runtime_monitoring_rules_path,
        alertmanager_targets_raw=settings.runtime_monitoring_alertmanager_targets,
        include_localhost_targets=settings.runtime_monitoring_include_localhost_targets,
    )
    return PlainTextResponse(rendered.config, media_type="text/plain; charset=utf-8")


@router.get("/status", response_model=MonitoringStatusOut)
async def monitoring_status(
    session: AsyncSession = Depends(get_db_session),
) -> MonitoringStatusOut:
    settings = get_settings()
    settings_map = await cluster_settings_service.get_settings_map(session)
    paths = monitoring_service.resolve_monitoring_paths(
        config_path=settings.runtime_monitoring_prometheus_config_path,
        candidate_path=settings.runtime_monitoring_prometheus_candidate_path,
        backup_path=settings.runtime_monitoring_prometheus_backup_path,
    )
    api_targets = _split_csv(settings_map.get("monitoring_api_targets", ""))
    node_exporter_targets = _split_csv(settings_map.get("monitoring_node_exporter_targets", ""))
    alertmanager_targets = _split_csv(settings_map.get("monitoring_alertmanager_targets", ""))

    return MonitoringStatusOut(
        enabled=settings.runtime_monitoring_enable,
        config_path=str(paths.config_path),
        candidate_path=str(paths.candidate_path),
        backup_path=str(paths.backup_path),
        config_exists=paths.config_path.exists(),
        config_sha256=settings_map.get("monitoring_config_sha256", ""),
        api_targets=api_targets,
        node_exporter_targets=node_exporter_targets,
        alertmanager_targets=alertmanager_targets,
        api_target_count=_safe_int(
            settings_map.get("monitoring_api_target_count", "0"),
            default=len(api_targets),
        ),
        node_exporter_target_count=_safe_int(
            settings_map.get("monitoring_node_exporter_target_count", "0"),
            default=len(node_exporter_targets),
        ),
        alertmanager_target_count=_safe_int(
            settings_map.get("monitoring_alertmanager_target_count", "0"),
            default=len(alertmanager_targets),
        ),
        last_sync_at=settings_map.get("monitoring_last_sync_at", ""),
        last_apply_status=settings_map.get("monitoring_last_apply_status", "unknown"),
        last_apply_error=settings_map.get("monitoring_last_apply_error", ""),
    )
