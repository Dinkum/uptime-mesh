from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session, get_writable_db_session
from app.models.node import Node
from app.schemas.etcd import (
    EtcdEndpointHealthOut,
    EtcdMemberAddRequest,
    EtcdMemberOut,
    EtcdQuorumOut,
    EtcdQuorumReconcileCandidateOut,
    EtcdQuorumReconcileOut,
    EtcdStatusOut,
)
from app.schemas.snapshots import SnapshotRunOut
from app.services import etcd as etcd_service
from app.services import snapshots as snapshot_service
from app.services.events import record_event
from uuid import uuid4

router = APIRouter(prefix="/etcd", tags=["etcd"])


def _is_etcd_eligible_node(node: Node) -> bool:
    roles = node.roles if isinstance(node.roles, list) else []
    normalized = {str(role).strip().lower() for role in roles if str(role).strip()}
    if not normalized:
        return True
    # Legacy role labels are treated as auto/eligible to keep old nodes operable.
    return bool(normalized & {"backend_server", "reverse_proxy", "auto", "worker", "gateway", "general", "node"})


def _node_peer_url(node: Node) -> str:
    status = node.status if isinstance(node.status, dict) else {}
    peer_from_status = status.get("etcd_peer_url")
    if isinstance(peer_from_status, str) and peer_from_status.strip():
        return peer_from_status.strip()

    labels = node.labels if isinstance(node.labels, dict) else {}
    peer_from_label = labels.get("etcd_peer_url")
    if isinstance(peer_from_label, str) and peer_from_label.strip():
        return peer_from_label.strip()

    if node.mesh_ip and node.mesh_ip.strip():
        return f"http://{node.mesh_ip.strip()}:2380"

    if node.api_endpoint and node.api_endpoint.strip():
        parsed = urlparse(node.api_endpoint.strip())
        if parsed.hostname:
            return f"http://{parsed.hostname}:2380"
    return ""


def _build_quorum_payload(
    *,
    enabled: bool,
    configured: bool,
    desired_member_ids: list[str],
    current_member_ids: list[str],
    endpoint_count: int,
    healthy_endpoint_count: int,
    detail: str = "",
) -> EtcdQuorumOut:
    desired_set = set(desired_member_ids)
    current_set = set(current_member_ids)
    missing_member_ids = sorted(desired_set - current_set)
    extra_member_ids = sorted(current_set - desired_set)
    quorum_required = (len(current_member_ids) // 2) + 1 if current_member_ids else 0
    has_quorum = bool(current_member_ids) and healthy_endpoint_count >= quorum_required
    return EtcdQuorumOut(
        enabled=enabled,
        configured=configured,
        desired_member_ids=sorted(desired_member_ids),
        current_member_ids=sorted(current_member_ids),
        missing_member_ids=missing_member_ids,
        extra_member_ids=extra_member_ids,
        endpoint_count=endpoint_count,
        healthy_endpoint_count=healthy_endpoint_count,
        quorum_required=quorum_required,
        has_quorum=has_quorum,
        detail=detail,
    )


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


@router.get("/quorum", response_model=EtcdQuorumOut)
async def etcd_quorum(
    session: AsyncSession = Depends(get_db_session),
) -> EtcdQuorumOut:
    settings = get_settings()
    endpoints = [item.strip() for item in settings.etcd_endpoints.split(",") if item.strip()]
    configured = bool(endpoints)
    result = await session.execute(select(Node))
    nodes = list(result.scalars().all())
    desired_member_ids = [node.id for node in nodes if _is_etcd_eligible_node(node)]

    if not settings.etcd_enabled or not configured:
        return _build_quorum_payload(
            enabled=settings.etcd_enabled,
            configured=configured,
            desired_member_ids=desired_member_ids,
            current_member_ids=[],
            endpoint_count=0,
            healthy_endpoint_count=0,
            detail="etcd disabled or unconfigured",
        )

    try:
        members = await etcd_service.member_list()
        health = await etcd_service.endpoint_health()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Unable to evaluate etcd quorum: {exc}") from exc

    current_member_ids = [item.name for item in members if item.name]
    healthy_endpoint_count = sum(1 for item in health if item.healthy)
    return _build_quorum_payload(
        enabled=True,
        configured=True,
        desired_member_ids=desired_member_ids,
        current_member_ids=current_member_ids,
        endpoint_count=len(health),
        healthy_endpoint_count=healthy_endpoint_count,
        detail="",
    )


@router.post("/quorum/reconcile", response_model=EtcdQuorumReconcileOut)
async def reconcile_etcd_quorum(
    dry_run: bool = False,
    session: AsyncSession = Depends(get_writable_db_session),
) -> EtcdQuorumReconcileOut:
    settings = get_settings()
    configured = bool([item.strip() for item in settings.etcd_endpoints.split(",") if item.strip()])
    if not settings.etcd_enabled or not configured:
        raise HTTPException(status_code=503, detail="etcd is disabled or unconfigured")

    result = await session.execute(select(Node))
    nodes = list(result.scalars().all())
    eligible_nodes = sorted(
        (node for node in nodes if _is_etcd_eligible_node(node)),
        key=lambda item: item.id,
    )

    try:
        members = await etcd_service.member_list()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Unable to list etcd members: {exc}") from exc

    by_name = {item.name: item for item in members if item.name}
    candidates: list[EtcdQuorumReconcileCandidateOut] = []
    added_count = 0
    skipped_count = 0
    failed_count = 0

    for node in eligible_nodes:
        existing = by_name.get(node.id)
        if existing is not None:
            candidates.append(
                EtcdQuorumReconcileCandidateOut(
                    node_id=node.id,
                    peer_url=(existing.peer_urls[0] if existing.peer_urls else ""),
                    action="exists",
                    member_id=existing.member_id,
                )
            )
            continue

        peer_url = _node_peer_url(node)
        if not peer_url:
            skipped_count += 1
            candidates.append(
                EtcdQuorumReconcileCandidateOut(
                    node_id=node.id,
                    action="skipped",
                    reason="missing_peer_url",
                )
            )
            continue

        if dry_run:
            candidates.append(
                EtcdQuorumReconcileCandidateOut(
                    node_id=node.id,
                    peer_url=peer_url,
                    action="would_add",
                )
            )
            continue

        try:
            added = await etcd_service.member_add(
                name=node.id,
                peer_urls=[peer_url],
                is_learner=False,
            )
            by_name[node.id] = etcd_service.EtcdMember(
                member_id=added.member_id,
                name=node.id,
                peer_urls=added.peer_urls,
                client_urls=[],
                is_learner=False,
            )
            added_count += 1
            candidates.append(
                EtcdQuorumReconcileCandidateOut(
                    node_id=node.id,
                    peer_url=peer_url,
                    action="added",
                    member_id=added.member_id,
                )
            )
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="member.add.auto",
                level="INFO",
                fields={
                    "node_id": node.id,
                    "member_id": added.member_id,
                    "peer_url": peer_url,
                },
            )
        except Exception as exc:  # noqa: BLE001
            failed_count += 1
            candidates.append(
                EtcdQuorumReconcileCandidateOut(
                    node_id=node.id,
                    peer_url=peer_url,
                    action="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    if not dry_run and added_count > 0:
        await session.commit()

    return EtcdQuorumReconcileOut(
        dry_run=dry_run,
        desired_member_count=len(eligible_nodes),
        current_member_count=len(by_name),
        added_count=added_count,
        skipped_count=skipped_count,
        failed_count=failed_count,
        candidates=candidates,
    )


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
