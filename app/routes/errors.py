from __future__ import annotations

from typing import NoReturn

from fastapi import HTTPException

from app.logger import BoundLogger
from app.services import lxd as lxd_service


def raise_lxd_http_error(
    exc: lxd_service.LXDOperationError,
    *,
    logger: BoundLogger,
    event: str,
    message: str,
) -> NoReturn:
    status_code = 503 if isinstance(exc, lxd_service.LXDUnavailableError) else 409
    logger.warning(
        event,
        message,
        action=exc.action,
        detail=exc.detail,
        status_code=status_code,
    )
    raise HTTPException(
        status_code=status_code,
        detail=f"LXD operation failed ({exc.action}): {exc.detail}",
    ) from exc
