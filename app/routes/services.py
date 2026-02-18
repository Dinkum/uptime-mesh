from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.logger import get_logger
from app.schemas.services import ServiceCreate, ServiceOut, ServiceRollback, ServiceUpdate
from app.services import lxd as lxd_service
from app.services import services as service_service

router = APIRouter(prefix="/services", tags=["services"])
_logger = get_logger("api.services")


def _raise_lxd_http_error(exc: lxd_service.LXDOperationError) -> None:
    status_code = 503 if isinstance(exc, lxd_service.LXDUnavailableError) else 409
    _logger.warning(
        "service.lxd_error",
        "Service action failed due to LXD operation error",
        action=exc.action,
        detail=exc.detail,
        status_code=status_code,
    )
    raise HTTPException(
        status_code=status_code,
        detail=f"LXD operation failed ({exc.action}): {exc.detail}",
    ) from exc


@router.get("", response_model=List[ServiceOut])
async def list_services(
    session: AsyncSession = Depends(get_db_session),
) -> List[ServiceOut]:
    services = await service_service.list_services(session)
    return [ServiceOut.model_validate(service) for service in services]


@router.get("/{service_id}", response_model=ServiceOut)
async def get_service(
    service_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> ServiceOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return ServiceOut.model_validate(service)


@router.post("", response_model=ServiceOut, status_code=status.HTTP_201_CREATED)
async def create_service(
    payload: ServiceCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ServiceOut:
    if await service_service.get_service(session, payload.id):
        raise HTTPException(status_code=409, detail="Service id already exists")
    if await service_service.get_service_by_name(session, payload.name):
        raise HTTPException(status_code=409, detail="Service name already exists")
    service = await service_service.create_service(session, payload)
    return ServiceOut.model_validate(service)


@router.patch("/{service_id}", response_model=ServiceOut)
async def update_service(
    service_id: str,
    payload: ServiceUpdate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ServiceOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    updated = await service_service.update_service(session, service, payload)
    return ServiceOut.model_validate(updated)


@router.post("/{service_id}/rollout", response_model=ServiceOut)
async def rollout_service(
    service_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ServiceOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    try:
        updated = await service_service.rollout_service(session, service)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ServiceOut.model_validate(updated)


@router.post("/{service_id}/rollback", response_model=ServiceOut)
async def rollback_service(
    service_id: str,
    payload: ServiceRollback | None = None,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ServiceOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    target_generation = payload.target_generation if payload else None
    try:
        updated = await service_service.rollback_service(session, service, target_generation)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ServiceOut.model_validate(updated)


@router.post("/{service_id}/apply-pinned", response_model=ServiceOut)
async def apply_pinned_service_placement(
    service_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ServiceOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    try:
        updated = await service_service.apply_pinned_placement(session, service)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ServiceOut.model_validate(updated)
