from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session, get_writable_db_session
from app.logger import get_logger
from app.metrics import is_enabled as metrics_backend_available
from app.metrics import metrics_content_type, render_metrics
from app.services import preflight as preflight_service
from app.services import runtime_inventory, simulator

router = APIRouter()
_logger = get_logger("api.system")


def _redact_url(value: str) -> str:
    if "@" not in value:
        return value
    scheme, _, rest = value.partition("://")
    _, _, host = rest.rpartition("@")
    return f"{scheme}://<redacted>@{host}"


@router.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui")


@router.get("/health", tags=["system"])
async def health() -> Dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    _logger.info("health.check", "Health check", status="ok")
    return {"status": "ok", "time": now}


@router.get("/version", tags=["system"])
async def version() -> Dict[str, str]:
    settings = get_settings()
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "manifest_version": settings.app_manifest_version,
        "channel": settings.app_release_channel,
        "agent_version": settings.app_agent_version,
        "version_source": settings.app_version_source_path,
        "env": settings.app_env,
    }


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    settings = get_settings()
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Metrics are disabled.")
    if not metrics_backend_available():
        raise HTTPException(status_code=503, detail="Prometheus backend is not available.")
    payload = render_metrics()
    return Response(content=payload, media_type=metrics_content_type())


@router.get("/system/preflight", tags=["system"])
async def preflight(session: AsyncSession = Depends(get_db_session)) -> Dict[str, object]:
    return await preflight_service.build_preflight_report(session, get_settings())


@router.get("/system/runtime-inventory", tags=["system"])
async def runtime_inventory_report(
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, object]:
    return await runtime_inventory.build_runtime_inventory(session, get_settings())


@router.post("/system/simulator/seed", tags=["system"], status_code=status.HTTP_201_CREATED)
async def simulator_seed(
    session: AsyncSession = Depends(get_writable_db_session),
) -> Dict[str, object]:
    settings = get_settings()
    if settings.app_env.strip().lower() in {"prod", "production"}:
        raise HTTPException(status_code=403, detail="Simulator seed is disabled in production.")
    return await simulator.seed_local_simulator(session)


@router.get("/system/runbook", tags=["system"], response_class=PlainTextResponse)
async def recovery_runbook() -> PlainTextResponse:
    settings = get_settings()
    body = "\n".join(
        [
            "# UptimeMesh Recovery Runbook",
            "",
            "## State",
            f"- Database URL: `{_redact_url(settings.database_url)}`",
            f"- Managed config: `{settings.managed_config_path}`",
            f"- Snapshot directory: `{settings.etcd_snapshot_dir}`",
            f"- Support bundle directory: `{settings.support_bundle_dir}`",
            "",
            "## Checks",
            "- `GET /health` checks API liveness.",
            "- `GET /system/preflight` lists current readiness blockers.",
            "- `GET /system/runtime-inventory` lists managed runtime references and drift flags.",
            "",
            "## Snapshots",
            "- `GET /etcd/snapshots` lists snapshot runs.",
            "- `GET /etcd/snapshots/<snapshot-id>/download` downloads a completed snapshot.",
            "- `POST /etcd/snapshots/<snapshot-id>/restore` restores a completed snapshot.",
            "",
            "## Emergency Actions",
            "- Stop the API before replacing DB files.",
            "- Restore etcd from a verified snapshot before resuming writes.",
            "- Inspect warning events named `replica.runtime_drift` after restart.",
            "- Rotate sessions from Settings after credential exposure.",
            "",
        ]
    )
    return PlainTextResponse(body, media_type="text/markdown; charset=utf-8")
