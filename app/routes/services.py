from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.services import ServiceCreate, ServiceOut, ServiceRollback, ServiceUpdate
from app.services import services as service_service

router = APIRouter(prefix="/services", tags=["services"])


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
    updated = await service_service.rollout_service(session, service)
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
    updated = await service_service.rollback_service(session, service, target_generation)
    return ServiceOut.model_validate(updated)
