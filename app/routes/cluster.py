from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.cluster import (
    ClusterBootstrapOut,
    ClusterBootstrapRequest,
    HeartbeatOut,
    HeartbeatRequest,
    JoinTokenCreate,
    JoinTokenOut,
    NodeJoinOut,
    NodeJoinRequest,
    NodeLeaseOut,
)
from app.services import cluster as cluster_service

router = APIRouter(prefix="/cluster", tags=["cluster"])


@router.post("/bootstrap", response_model=ClusterBootstrapOut)
async def bootstrap_cluster(
    payload: ClusterBootstrapRequest,
    request: Request,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ClusterBootstrapOut:
    requested_by = getattr(request.state, "auth_user", None)
    bootstrapped, core_token, worker_token = await cluster_service.bootstrap_cluster(
        session,
        payload=payload,
        requested_by=requested_by,
    )
    return ClusterBootstrapOut(
        bootstrapped=bootstrapped,
        core_token=core_token,
        worker_token=worker_token,
    )


@router.post("/join-tokens", response_model=JoinTokenOut, status_code=status.HTTP_201_CREATED)
async def create_join_token(
    payload: JoinTokenCreate,
    request: Request,
    session: AsyncSession = Depends(get_writable_db_session),
) -> JoinTokenOut:
    requested_by = getattr(request.state, "auth_user", None)
    return await cluster_service.create_join_token(
        session,
        role=payload.role,
        ttl_seconds=payload.ttl_seconds,
        issued_by=requested_by,
    )


@router.post("/join", response_model=NodeJoinOut)
async def join_node(
    payload: NodeJoinRequest,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeJoinOut:
    joined = await cluster_service.join_node(session, payload)
    if joined is None:
        raise HTTPException(status_code=401, detail="Invalid, expired, or already-used join token.")
    return joined


@router.post("/heartbeat", response_model=HeartbeatOut)
async def heartbeat(
    payload: HeartbeatRequest,
    session: AsyncSession = Depends(get_writable_db_session),
) -> HeartbeatOut:
    lease = await cluster_service.apply_heartbeat(
        session,
        node_id=payload.node_id,
        lease_token=payload.lease_token,
        ttl_seconds=payload.ttl_seconds,
        status_patch=payload.status_patch,
        signed_at=payload.signed_at,
        signature=payload.signature,
    )
    if lease is None:
        raise HTTPException(status_code=401, detail="Invalid node id or lease token.")
    return lease


@router.get("/leases", response_model=List[NodeLeaseOut])
async def list_leases(
    session: AsyncSession = Depends(get_db_session),
) -> List[NodeLeaseOut]:
    return await cluster_service.list_node_leases(session)
