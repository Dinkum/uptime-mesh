from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.cluster import (
    ClusterPeerOut,
    ClusterBootstrapOut,
    ClusterBootstrapRequest,
    ContentActiveOut,
    HeartbeatOut,
    HeartbeatRequest,
    JoinTokenCreate,
    JoinTokenOut,
    SwimMemberOut,
    SwimReportOut,
    SwimReportRequest,
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
    bootstrapped, worker_token = await cluster_service.bootstrap_cluster(
        session,
        payload=payload,
        requested_by=requested_by,
    )
    return ClusterBootstrapOut(
        bootstrapped=bootstrapped,
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
    session: AsyncSession = Depends(get_db_session),
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


@router.get("/peers", response_model=List[ClusterPeerOut])
async def list_peers(
    node_id: str,
    lease_token: str,
    session: AsyncSession = Depends(get_db_session),
) -> List[ClusterPeerOut]:
    is_valid = await cluster_service.validate_node_lease_token(
        session,
        node_id=node_id,
        lease_token=lease_token,
    )
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid node credentials.")
    peers = await cluster_service.list_cluster_peers(
        session,
        node_id=node_id,
        lease_token=lease_token,
    )
    return [ClusterPeerOut.model_validate(item) for item in peers]


@router.post("/swim/report", response_model=SwimReportOut)
async def report_swim(
    payload: SwimReportRequest,
    session: AsyncSession = Depends(get_db_session),
) -> SwimReportOut:
    accepted, updated_at = await cluster_service.record_swim_report(
        session,
        node_id=payload.node_id,
        lease_token=payload.lease_token,
        incarnation=payload.incarnation,
        state=payload.state,
        flags=payload.flags,
        peers=payload.peers,
    )
    if not accepted:
        raise HTTPException(status_code=401, detail="Invalid node credentials.")
    return SwimReportOut(node_id=payload.node_id, accepted=True, updated_at=updated_at)


@router.get("/swim", response_model=List[SwimMemberOut])
async def list_swim(
    session: AsyncSession = Depends(get_db_session),
) -> List[SwimMemberOut]:
    members = await cluster_service.list_swim_members(session)
    rows = [SwimMemberOut.model_validate(item) for item in members.values()]
    rows.sort(key=lambda item: item.node_id)
    return rows


@router.get("/content/active", response_model=ContentActiveOut)
async def active_content(
    node_id: str,
    lease_token: str,
    session: AsyncSession = Depends(get_db_session),
) -> ContentActiveOut:
    is_valid = await cluster_service.validate_node_lease_token(
        session,
        node_id=node_id,
        lease_token=lease_token,
    )
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid node credentials.")
    payload = await cluster_service.get_active_content(session)
    return ContentActiveOut.model_validate(payload)
