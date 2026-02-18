from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.logger import get_logger
from app.schemas.replicas import (
    ReplicaCreate,
    ReplicaMove,
    ReplicaOut,
    ReplicaRestore,
    ReplicaUpdate,
)
from app.services import nodes as node_service
from app.services import lxd as lxd_service
from app.services import replicas as replica_service
from app.services import services as service_service

router = APIRouter(prefix="/replicas", tags=["replicas"])
_logger = get_logger("api.replicas")


def _raise_lxd_http_error(exc: lxd_service.LXDOperationError) -> None:
    status_code = 503 if isinstance(exc, lxd_service.LXDUnavailableError) else 409
    _logger.warning(
        "replica.lxd_error",
        "Replica action failed due to LXD operation error",
        action=exc.action,
        detail=exc.detail,
        status_code=status_code,
    )
    raise HTTPException(
        status_code=status_code,
        detail=f"LXD operation failed ({exc.action}): {exc.detail}",
    ) from exc


@router.get("", response_model=List[ReplicaOut])
async def list_replicas(
    session: AsyncSession = Depends(get_db_session),
) -> List[ReplicaOut]:
    replicas = await replica_service.list_replicas(session)
    return [ReplicaOut.model_validate(replica) for replica in replicas]


@router.get("/{replica_id}", response_model=ReplicaOut)
async def get_replica(
    replica_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    return ReplicaOut.model_validate(replica)


@router.post("", response_model=ReplicaOut, status_code=status.HTTP_201_CREATED)
async def create_replica(
    payload: ReplicaCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    if await replica_service.get_replica(session, payload.id):
        raise HTTPException(status_code=409, detail="Replica id already exists")
    if await service_service.get_service(session, payload.service_id) is None:
        raise HTTPException(status_code=404, detail="Service not found")
    if await node_service.get_node(session, payload.node_id) is None:
        raise HTTPException(status_code=404, detail="Node not found")
    try:
        replica = await replica_service.create_replica(session, payload)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(replica)


@router.patch("/{replica_id}", response_model=ReplicaOut)
async def update_replica(
    replica_id: str,
    payload: ReplicaUpdate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    try:
        updated = await replica_service.update_replica(session, replica, payload)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(updated)


@router.post("/{replica_id}/move", response_model=ReplicaOut)
async def move_replica(
    replica_id: str,
    payload: ReplicaMove,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    if await node_service.get_node(session, payload.target_node_id) is None:
        raise HTTPException(status_code=404, detail="Target node not found")
    try:
        updated = await replica_service.move_replica(session, replica, payload.target_node_id)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(updated)


@router.post("/{replica_id}/restart", response_model=ReplicaOut)
async def restart_replica(
    replica_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    try:
        updated = await replica_service.restart_replica(session, replica)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(updated)


@router.post("/{replica_id}/snapshot", response_model=ReplicaOut)
async def snapshot_replica(
    replica_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    try:
        updated = await replica_service.snapshot_replica(session, replica)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(updated)


@router.post("/{replica_id}/restore", response_model=ReplicaOut)
async def restore_replica(
    replica_id: str,
    payload: ReplicaRestore | None = None,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ReplicaOut:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    snapshot_id = payload.snapshot_id if payload else None
    try:
        updated = await replica_service.restore_replica(session, replica, snapshot_id)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
    return ReplicaOut.model_validate(updated)


@router.delete("/{replica_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_replica(
    replica_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> None:
    replica = await replica_service.get_replica(session, replica_id)
    if replica is None:
        raise HTTPException(status_code=404, detail="Replica not found")
    try:
        await replica_service.delete_replica(session, replica)
    except lxd_service.LXDOperationError as exc:
        _raise_lxd_http_error(exc)
