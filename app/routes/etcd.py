from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_writable_db_session
from app.schemas.etcd import (
    EtcdEndpointHealthOut,
    EtcdMemberAddRequest,
    EtcdMemberOut,
    EtcdStatusOut,
)
from app.schemas.snapshots import SnapshotRunOut
from app.services import etcd as etcd_service
from app.services import snapshots as snapshot_service
from app.services.events import record_event
from uuid import uuid4

router = APIRouter(prefix="/etcd", tags=["etcd"])


@router.get("/status", response_model=EtcdStatusOut)
async def etcd_status() -> EtcdStatusOut:
    settings = get_settings()
    endpoints = [item.strip() for item in settings.etcd_endpoints.split(",") if item.strip()]
    configured = bool(endpoints)
    if not settings.etcd_enabled or not configured:
        return EtcdStatusOut(
            enabled=settings.etcd_enabled,
            configured=configured,
            endpoints=endpoints,
            healthy=False,
            details=[],
        )
    try:
        details = await etcd_service.endpoint_health()
    except Exception as exc:  # noqa: BLE001
        return EtcdStatusOut(
            enabled=settings.etcd_enabled,
            configured=configured,
            endpoints=endpoints,
            healthy=False,
            details=[
                EtcdEndpointHealthOut(
                    endpoint=endpoint,
                    healthy=False,
                    error=f"{type(exc).__name__}: {exc}",
                    took_seconds=0.0,
                )
                for endpoint in endpoints
            ],
        )
    healthy = bool(details) and all(item.healthy for item in details)
    return EtcdStatusOut(
        enabled=True,
        configured=True,
        endpoints=endpoints,
        healthy=healthy,
        details=[
            EtcdEndpointHealthOut(
                endpoint=item.endpoint,
                healthy=item.healthy,
                error=item.error,
                took_seconds=item.took_seconds,
            )
            for item in details
        ],
    )


@router.get("/members", response_model=list[EtcdMemberOut])
async def etcd_members() -> list[EtcdMemberOut]:
    try:
        members = await etcd_service.member_list()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Unable to list etcd members: {exc}") from exc
    return [
        EtcdMemberOut(
            member_id=item.member_id,
            name=item.name,
            peer_urls=item.peer_urls,
            client_urls=item.client_urls,
            is_learner=item.is_learner,
        )
        for item in members
    ]


@router.post("/members", response_model=EtcdMemberOut)
async def add_etcd_member(
    payload: EtcdMemberAddRequest,
    session: AsyncSession = Depends(get_writable_db_session),
) -> EtcdMemberOut:
    try:
        result = await etcd_service.member_add(
            name=payload.name,
            peer_urls=payload.peer_urls,
            is_learner=payload.is_learner,
        )
        members = await etcd_service.member_list()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Unable to add etcd member: {exc}") from exc

    selected = next((item for item in members if item.member_id == result.member_id), None)
    if selected is None:
        selected = next((item for item in members if item.name == payload.name), None)
    if selected is None:
        selected = etcd_service.EtcdMember(
            member_id=result.member_id,
            name=payload.name,
            peer_urls=result.peer_urls,
            client_urls=[],
            is_learner=payload.is_learner,
        )

    await record_event(
        session,
        event_id=str(uuid4()),
        category="etcd",
        name="member.add",
        level="INFO",
        fields={
            "member_id": selected.member_id,
            "name": selected.name,
            "peer_urls": ",".join(selected.peer_urls),
            "is_learner": selected.is_learner,
        },
    )
    await session.commit()
    return EtcdMemberOut(
        member_id=selected.member_id,
        name=selected.name,
        peer_urls=selected.peer_urls,
        client_urls=selected.client_urls,
        is_learner=selected.is_learner,
    )


@router.delete("/members/{member_id}")
async def remove_etcd_member(
    member_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> dict[str, str]:
    try:
        await etcd_service.member_remove(member_id=member_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Unable to remove etcd member: {exc}") from exc

    await record_event(
        session,
        event_id=str(uuid4()),
        category="etcd",
        name="member.remove",
        level="INFO",
        fields={"member_id": member_id},
    )
    await session.commit()
    return {"status": "removed", "member_id": member_id}


@router.post("/snapshots/{snapshot_id}/restore", response_model=SnapshotRunOut)
async def restore_snapshot(
    snapshot_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> SnapshotRunOut:
    snapshot = await snapshot_service.get_snapshot(session, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    restored = await snapshot_service.restore_snapshot(session, snapshot)
    return SnapshotRunOut.model_validate(restored)
