from __future__ import annotations

from typing import NoReturn
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.logger import get_logger
from app.routes.errors import raise_lxd_http_error
from app.schemas.services import ServiceCreate, ServiceOut, ServiceRollback, ServiceUpdate
from app.schemas.survivor import ServiceStateOut, SurvivorReportOut
from app.services import docker as docker_service
from app.services import lxd as lxd_service
from app.services import service_state as service_state_service
from app.services import services as service_service
from app.services import survivor as survivor_service

router = APIRouter(prefix="/services", tags=["services"])
_logger = get_logger("api.services")


def _raise_service_lxd_http_error(exc: lxd_service.LXDOperationError) -> NoReturn:
    raise_lxd_http_error(
        exc,
        logger=_logger,
        event="service.lxd_error",
        message="Service action failed due to LXD operation error",
    )


def _raise_service_docker_http_error(exc: docker_service.DockerOperationError) -> NoReturn:
    raise HTTPException(
        status_code=502,
        detail=f"Docker operation failed ({exc.action}): {exc.detail}",
    )


@router.get("", response_model=List[ServiceOut])
async def list_services(
    session: AsyncSession = Depends(get_db_session),
) -> List[ServiceOut]:
    services = await service_service.list_services(session)
    return [ServiceOut.model_validate(service) for service in services]


@router.get("/state", response_model=List[ServiceStateOut])
async def list_service_states(
    session: AsyncSession = Depends(get_db_session),
) -> List[ServiceStateOut]:
    return await service_state_service.list_service_states(session)


@router.get("/survivor/report", response_model=SurvivorReportOut)
async def get_survivor_report(
    session: AsyncSession = Depends(get_db_session),
) -> SurvivorReportOut:
    return await survivor_service.build_survivor_report(session)


@router.get("/{service_id}/state", response_model=ServiceStateOut)
async def get_service_state(
    service_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> ServiceStateOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return await service_state_service.build_service_state(session, service=service)


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
    try:
        service = await service_service.create_service(session, payload)
    except lxd_service.LXDOperationError as exc:
        _raise_service_lxd_http_error(exc)
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
    try:
        updated = await service_service.update_service(session, service, payload)
    except lxd_service.LXDOperationError as exc:
        _raise_service_lxd_http_error(exc)
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
        _raise_service_lxd_http_error(exc)
    except docker_service.DockerOperationError as exc:
        _raise_service_docker_http_error(exc)
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
        _raise_service_lxd_http_error(exc)
    except docker_service.DockerOperationError as exc:
        _raise_service_docker_http_error(exc)
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
        _raise_service_lxd_http_error(exc)
    except docker_service.DockerOperationError as exc:
        _raise_service_docker_http_error(exc)
    return ServiceOut.model_validate(updated)
