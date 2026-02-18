from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.models.node import Node
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.replicas import ReplicaCreate, ReplicaUpdate
from app.services.events import record_event
from app.services import lxd as lxd_service

_logger = get_logger("services.replicas")
_settings = get_settings()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _container_name_for(replica: Replica, service: Service) -> str:
    status = replica.status if isinstance(replica.status, dict) else {}
    existing = status.get("lxd_container_name")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()
    return lxd_service.container_name(service.name, replica.id)


async def _service_and_node(
    session: AsyncSession,
    *,
    service_id: str,
    node_id: str,
) -> tuple[Service, Node]:
    service = await session.get(Service, service_id)
    if service is None:
        raise lxd_service.LXDOperationError("replica.resolve", f"service not found: {service_id}")
    node = await session.get(Node, node_id)
    if node is None:
        raise lxd_service.LXDOperationError("replica.resolve", f"node not found: {node_id}")
    return service, node


def _merge_lxd_status(status: dict[str, object], **fields: object) -> dict[str, object]:
    merged = dict(status)
    merged.update(fields)
    return merged


async def list_replicas(session: AsyncSession, limit: int = 200) -> List[Replica]:
    result = await session.execute(select(Replica).limit(limit))
    return list(result.scalars().all())


async def get_replica(session: AsyncSession, replica_id: str) -> Optional[Replica]:
    result = await session.execute(select(Replica).where(Replica.id == replica_id))
    return result.scalar_one_or_none()


async def list_replicas_for_service(
    session: AsyncSession,
    service_id: str,
    limit: int = 1000,
) -> List[Replica]:
    result = await session.execute(
        select(Replica).where(Replica.service_id == service_id).limit(limit)
    )
    return list(result.scalars().all())


async def create_replica(session: AsyncSession, payload: ReplicaCreate) -> Replica:
    async with _logger.operation(
        "replica.create",
        "Creating replica",
        replica_id=payload.id,
        service_id=payload.service_id,
        node_id=payload.node_id,
    ) as op:
        service, node = await _service_and_node(
            session,
            service_id=payload.service_id,
            node_id=payload.node_id,
        )
        status = dict(payload.status or {})

        if _settings.lxd_enabled:
            spec = lxd_service.build_container_spec(
                service_name=service.name,
                service_spec=service.spec or {},
                replica_id=payload.id,
                node_name=node.name,
                desired_state=payload.desired_state,
            )
            op.step(
                "lxd.spec",
                "Resolved container spec",
                container=spec.name,
                project=spec.project,
                target_node=spec.target_node,
            )
            await lxd_service.ensure_container(spec)
            runtime_state = await lxd_service.container_status(
                name=spec.name,
                project=spec.project,
            )
            status = _merge_lxd_status(
                status,
                lxd_container_name=spec.name,
                lxd_project=spec.project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="create",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.ensure", "Ensured LXD container", state=runtime_state)
        else:
            status = _merge_lxd_status(
                status,
                lxd_last_action="create.skipped",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.skip", "Skipped LXD orchestration (disabled)")

        replica = Replica(
            id=payload.id,
            service_id=payload.service_id,
            node_id=payload.node_id,
            desired_state=payload.desired_state,
            status=status,
        )
        session.add(replica)
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.create",
            level="INFO",
            fields={
                "replica_id": payload.id,
                "service_id": payload.service_id,
                "node_id": payload.node_id,
                "lxd_enabled": _settings.lxd_enabled,
            },
        )
        await session.commit()
        await session.refresh(replica)
        _logger.info("replicas.create", "Created replica", replica_id=replica.id)
        return replica


async def update_replica(
    session: AsyncSession,
    replica: Replica,
    payload: ReplicaUpdate,
) -> Replica:
    changed = False
    status_map = dict(replica.status or {})
    if payload.desired_state is not None:
        replica.desired_state = payload.desired_state
        changed = True
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.update",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status_map.get("lxd_project") or _settings.lxd_project)
            desired = payload.desired_state.lower()
            if desired == "running":
                await lxd_service.start_container(name=container_name, project=project)
                runtime_state = "running"
            elif desired in {"stopped", "stop"}:
                await lxd_service.stop_container(name=container_name, project=project)
                runtime_state = "stopped"
            else:
                runtime_state = await lxd_service.container_status(
                    name=container_name,
                    project=project,
                )
            status_map = _merge_lxd_status(
                status_map,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="update.state",
                lxd_last_action_at=_utcnow_iso(),
            )
    if payload.status is not None:
        status_map = _merge_lxd_status(status_map, **payload.status)
        changed = True

    if changed:
        replica.status = status_map
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.update",
            level="INFO",
            fields={
                "replica_id": replica.id,
                "desired_state": replica.desired_state,
            },
        )

    await session.commit()
    await session.refresh(replica)
    return replica


async def move_replica(
    session: AsyncSession,
    replica: Replica,
    target_node_id: str,
) -> Replica:
    async with _logger.operation(
        "replica.move",
        "Moving replica",
        replica_id=replica.id,
        current_node_id=replica.node_id,
        target_node_id=target_node_id,
    ) as op:
        status = dict(replica.status or {})
        if _settings.lxd_enabled:
            service, target_node = await _service_and_node(
                session,
                service_id=replica.service_id,
                node_id=target_node_id,
            )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            op.step(
                "lxd.move",
                "Moving LXD container to target node",
                container=container_name,
                project=project,
                target_node=target_node.name,
            )
            await lxd_service.move_container(
                name=container_name,
                project=project,
                target_node=target_node.name,
            )
            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_target_node=target_node.name,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="move",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Container move complete", lxd_state=runtime_state)
        else:
            op.step("lxd.skip", "Skipped LXD move (disabled)")
        replica.node_id = target_node_id
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.move",
            level="INFO",
            fields={"replica_id": replica.id, "target_node_id": target_node_id},
        )
        op.step("event.record", "Recorded replica move event")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica move transaction")
        return replica


async def restart_replica(session: AsyncSession, replica: Replica) -> Replica:
    async with _logger.operation(
        "replica.restart",
        "Restarting replica",
        replica_id=replica.id,
    ) as op:
        status = dict(replica.status or {})
        status["last_restart_at"] = _utcnow_iso()
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.restart",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            op.step("lxd.restart", "Restarting LXD container", container=container_name, project=project)
            await lxd_service.restart_container(name=container_name, project=project)
            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="restart",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Container restart complete", lxd_state=runtime_state)
        else:
            op.step("lxd.skip", "Skipped LXD restart (disabled)")
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.restart",
            level="INFO",
            fields={"replica_id": replica.id},
        )
        op.step("event.record", "Recorded replica restart event")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica restart transaction")
        return replica


async def snapshot_replica(session: AsyncSession, replica: Replica) -> Replica:
    async with _logger.operation(
        "replica.snapshot",
        "Snapshotting replica",
        replica_id=replica.id,
    ) as op:
        status = dict(replica.status or {})
        snapshot_id = datetime.now(timezone.utc).strftime("snap-%Y%m%d%H%M%S")
        status["last_snapshot_at"] = _utcnow_iso()
        status["last_snapshot_id"] = snapshot_id
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.snapshot",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            op.step(
                "lxd.snapshot",
                "Creating LXD snapshot",
                container=container_name,
                project=project,
                snapshot_id=snapshot_id,
            )
            await lxd_service.snapshot_container(
                name=container_name,
                project=project,
                snapshot=snapshot_id,
            )
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_last_error="",
                lxd_last_action="snapshot",
                lxd_last_action_at=_utcnow_iso(),
            )
        else:
            op.step("lxd.skip", "Skipped LXD snapshot (disabled)", snapshot_id=snapshot_id)
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.snapshot",
            level="INFO",
            fields={"replica_id": replica.id, "snapshot_id": snapshot_id},
        )
        op.step("event.record", "Recorded replica snapshot event", snapshot_id=snapshot_id)
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica snapshot transaction")
        return replica


async def restore_replica(
    session: AsyncSession,
    replica: Replica,
    snapshot_id: Optional[str],
) -> Replica:
    async with _logger.operation(
        "replica.restore",
        "Restoring replica from snapshot",
        replica_id=replica.id,
        snapshot_id=snapshot_id or "",
    ) as op:
        status = dict(replica.status or {})
        resolved_snapshot = snapshot_id or str(status.get("last_snapshot_id") or "")
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.restore",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            if not resolved_snapshot:
                snapshots = await lxd_service.list_snapshots(name=container_name, project=project)
                op.step("lxd.snapshots", "Fetched container snapshots", count=len(snapshots))
                if snapshots:
                    resolved_snapshot = snapshots[-1]
                    op.step("snapshot.resolve", "Resolved latest snapshot", snapshot_id=resolved_snapshot)
            if not resolved_snapshot:
                raise lxd_service.LXDOperationError(
                    "replica.restore",
                    "no snapshot id provided and none available",
                )
            op.step(
                "lxd.restore",
                "Restoring LXD snapshot",
                container=container_name,
                project=project,
                snapshot_id=resolved_snapshot,
            )
            await lxd_service.restore_container(
                name=container_name,
                project=project,
                snapshot=resolved_snapshot,
            )
            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="restore",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Container restore complete", lxd_state=runtime_state)
        else:
            op.step("lxd.skip", "Skipped LXD restore (disabled)")
        status["last_restore_at"] = _utcnow_iso()
        if resolved_snapshot:
            status["last_restore_snapshot_id"] = resolved_snapshot
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.restore",
            level="INFO",
            fields={"replica_id": replica.id, "snapshot_id": resolved_snapshot or ""},
        )
        op.step("event.record", "Recorded replica restore event", snapshot_id=resolved_snapshot or "")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica restore transaction")
        return replica


async def delete_replica(session: AsyncSession, replica: Replica) -> None:
    replica_id = replica.id
    service_id = replica.service_id
    async with _logger.operation(
        "replica.delete",
        "Deleting replica",
        replica_id=replica_id,
        service_id=service_id,
    ) as op:
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.delete",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str((replica.status or {}).get("lxd_project") or _settings.lxd_project)
            op.step("lxd.delete", "Deleting LXD container", container=container_name, project=project)
            await lxd_service.delete_container(name=container_name, project=project)
        else:
            op.step("lxd.skip", "Skipped LXD delete (disabled)")
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.delete",
            level="INFO",
            fields={"replica_id": replica_id, "service_id": service_id},
        )
        op.step("event.record", "Recorded replica delete event")
        await session.delete(replica)
        await session.commit()
        op.step("db.commit", "Committed replica delete transaction")
        _logger.info("replicas.delete", "Deleted replica", replica_id=replica_id)
