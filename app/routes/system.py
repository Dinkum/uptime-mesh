from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse, Response

from app.config import get_settings
from app.logger import get_logger
from app.metrics import is_enabled as metrics_backend_available
from app.metrics import metrics_content_type, render_metrics

router = APIRouter()
_logger = get_logger("api.system")


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
