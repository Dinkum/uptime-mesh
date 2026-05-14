from __future__ import annotations

from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.node import Node
from app.schemas.etcd import (
    EtcdQuorumOut,
    EtcdQuorumReconcileCandidateOut,
    EtcdQuorumReconcileOut,
)
from app.services import etcd as etcd_service
from app.services.events import record_event

_ELIGIBLE_ROLE_NAMES = {
    "backend_server",
    "reverse_proxy",
    "auto",
    "worker",
    "gateway",
    "general",
    "node",
}


def is_etcd_eligible_node(node: Node) -> bool:
    roles = node.roles if isinstance(node.roles, list) else []
    normalized = {str(role).strip().lower() for role in roles if str(role).strip()}
    if not normalized:
        return True
    return bool(normalized & _ELIGIBLE_ROLE_NAMES)


def node_peer_url(node: Node) -> str:
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
    quorum_required = (len(current_member_ids) // 2) + 1 if current_member_ids else 0
    return EtcdQuorumOut(
        enabled=enabled,
        configured=configured,
        desired_member_ids=sorted(desired_member_ids),
        current_member_ids=sorted(current_member_ids),
        missing_member_ids=sorted(desired_set - current_set),
        extra_member_ids=sorted(current_set - desired_set),
        endpoint_count=endpoint_count,
        healthy_endpoint_count=healthy_endpoint_count,
        quorum_required=quorum_required,
        has_quorum=bool(current_member_ids) and healthy_endpoint_count >= quorum_required,
        detail=detail,
    )


async def evaluate_quorum(session: AsyncSession) -> EtcdQuorumOut:
    settings = get_settings()
    endpoints = [item.strip() for item in settings.etcd_endpoints.split(",") if item.strip()]
    configured = bool(endpoints)
    result = await session.execute(select(Node))
    nodes = list(result.scalars().all())
    desired_member_ids = [node.id for node in nodes if is_etcd_eligible_node(node)]

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

    members = await etcd_service.member_list()
    health = await etcd_service.endpoint_health()
    current_member_ids = [item.name for item in members if item.name]
    healthy_endpoint_count = sum(1 for item in health if item.healthy)
    return _build_quorum_payload(
        enabled=True,
        configured=True,
        desired_member_ids=desired_member_ids,
        current_member_ids=current_member_ids,
        endpoint_count=len(health),
        healthy_endpoint_count=healthy_endpoint_count,
    )


async def reconcile_quorum(
    session: AsyncSession,
    *,
    dry_run: bool = False,
) -> EtcdQuorumReconcileOut:
    settings = get_settings()
    configured = bool([item.strip() for item in settings.etcd_endpoints.split(",") if item.strip()])
    if not settings.etcd_enabled or not configured:
        raise RuntimeError("etcd is disabled or unconfigured")

    result = await session.execute(select(Node))
    nodes = list(result.scalars().all())
    eligible_nodes = sorted(
        (node for node in nodes if is_etcd_eligible_node(node)),
        key=lambda item: item.id,
    )
    members = await etcd_service.member_list()
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

        peer_url = node_peer_url(node)
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
