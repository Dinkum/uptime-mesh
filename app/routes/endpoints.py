from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.endpoints import EndpointCreate, EndpointOut, EndpointUpdate
from app.services import endpoints as endpoint_service
from app.services import replicas as replica_service

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


@router.get("", response_model=List[EndpointOut])
async def list_endpoints(
    session: AsyncSession = Depends(get_db_session),
) -> List[EndpointOut]:
    endpoints = await endpoint_service.list_endpoints(session)
    return [EndpointOut.model_validate(endpoint) for endpoint in endpoints]


@router.get("/{endpoint_id}", response_model=EndpointOut)
async def get_endpoint(
    endpoint_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> EndpointOut:
    endpoint = await endpoint_service.get_endpoint(session, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return EndpointOut.model_validate(endpoint)


@router.post("", response_model=EndpointOut, status_code=status.HTTP_201_CREATED)
async def create_endpoint(
    payload: EndpointCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> EndpointOut:
    if await endpoint_service.get_endpoint(session, payload.id):
        raise HTTPException(status_code=409, detail="Endpoint id already exists")
    if await replica_service.get_replica(session, payload.replica_id) is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    endpoint = await endpoint_service.create_endpoint(session, payload)
    return EndpointOut.model_validate(endpoint)


@router.patch("/{endpoint_id}", response_model=EndpointOut)
async def update_endpoint(
    endpoint_id: str,
    payload: EndpointUpdate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> EndpointOut:
    endpoint = await endpoint_service.get_endpoint(session, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    updated = await endpoint_service.update_endpoint(session, endpoint, payload)
    return EndpointOut.model_validate(updated)
