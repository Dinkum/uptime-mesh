from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from app.config import get_settings
from app.logger import get_logger

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
        "env": settings.app_env,
    }
