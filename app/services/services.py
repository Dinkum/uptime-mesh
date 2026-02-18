from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.replicas import ReplicaCreate, ReplicaUpdate
from app.schemas.services import ServiceCreate, ServiceUpdate
from app.services import lxd as lxd_service
from app.services import replicas as replica_service
from app.services.events import record_event

_logger = get_logger("services.services")
_settings = get_settings()


def _extract_pinned_placement(spec: dict[str, object]) -> tuple[list[dict[str, object]], bool]:
    placement = spec.get("placement")
    placement_map = placement if isinstance(placement, dict) else {}
    raw = placement_map.get("pinned_replicas", spec.get("pinned_replicas", []))
    strict = bool(placement_map.get("strict", spec.get("pinned_strict", False)))
    if not isinstance(raw, list):
        raise lxd_service.LXDOperationError(
            "service.pinned.spec",
            "pinned_replicas must be a list",
        )

    items: list[dict[str, object]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            raise lxd_service.LXDOperationError(
                "service.pinned.spec",
                f"pinned_replicas[{index}] must be an object",
            )
        replica_id = str(row.get("replica_id", "")).strip()
        node_id = str(row.get("node_id", "")).strip()
        desired_state = str(row.get("desired_state", "running")).strip() or "running"
        status = row.get("status")
        status_map = status if isinstance(status, dict) else {}
        if not replica_id:
            raise lxd_service.LXDOperationError(
                "service.pinned.spec",
                f"pinned_replicas[{index}].replica_id is required",
            )
        if not node_id:
            raise lxd_service.LXDOperationError(
                "service.pinned.spec",
                f"pinned_replicas[{index}].node_id is required",
            )
        items.append(
            {
                "replica_id": replica_id,
                "node_id": node_id,
                "desired_state": desired_state,
                "status": status_map,
            }
        )
    return items, strict


async def list_services(session: AsyncSession, limit: int = 100) -> List[Service]:
    async with _logger.operation("service.list", "Listing services", limit=limit) as op:
        result = await session.execute(select(Service).limit(limit))
        rows = list(result.scalars().all())
        op.step("db.select", "Fetched services", count=len(rows))
        return rows


async def get_service(session: AsyncSession, service_id: str) -> Optional[Service]:
    result = await session.execute(select(Service).where(Service.id == service_id))
    return result.scalar_one_or_none()


async def get_service_by_name(session: AsyncSession, name: str) -> Optional[Service]:
    result = await session.execute(select(Service).where(Service.name == name))
    return result.scalar_one_or_none()


async def create_service(session: AsyncSession, payload: ServiceCreate) -> Service:
    async with _logger.operation(
        "service.create",
        "Creating service",
        service_id=payload.id,
        name=payload.name,
    ) as op:
        service = Service(
            id=payload.id,
            name=payload.name,
            description=payload.description,
            spec=payload.spec,
        )
        session.add(service)
        op.step("db.insert", "Prepared service row")
        await record_event(
            session,
            event_id=str(uuid4()),
            category="services",
            name="service.create",
            level="INFO",
            fields={"service_id": payload.id, "name": payload.name},
        )
        op.step("event.record", "Recorded service create event")
        await session.commit()
        await session.refresh(service)
        op.step("db.commit", "Committed service create transaction")
        _logger.info("services.create", "Created service", service_id=service.id)
        return service


async def update_service(
    session: AsyncSession,
    service: Service,
    payload: ServiceUpdate,
) -> Service:
    async with _logger.operation(
        "service.update",
        "Updating service",
        service_id=service.id,
    ) as op:
        changed = False
        if payload.description is not None:
            service.description = payload.description
            changed = True
            op.step("description.update", "Updated service description")
        if payload.spec is not None:
            service.spec = payload.spec
            service.generation += 1
            changed = True
            op.step("spec.update", "Updated service spec", generation=service.generation)

        if changed:
            await record_event(
                session,
                event_id=str(uuid4()),
                category="services",
                name="service.update",
                level="INFO",
                fields={"service_id": service.id},
            )
            op.step("event.record", "Recorded service update event")
        else:
            op.step("change.none", "No service fields changed")

        await session.commit()
        await session.refresh(service)
        op.step("db.commit", "Committed service update transaction")
        return service


async def rollout_service(session: AsyncSession, service: Service) -> Service:
    async with _logger.operation(
        "service.rollout",
        "Requesting service rollout",
        service_id=service.id,
        generation=service.generation,
    ) as op:
        result = await session.execute(
            select(Replica).where(Replica.service_id == service.id).order_by(Replica.id.asc())
        )
        replicas = list(result.scalars().all())
        op.step("replica.select", "Fetched service replicas", count=len(replicas))

        rolled: list[tuple[str, str]] = []
        if _settings.lxd_enabled and replicas:
            for replica in replicas:
                snap = await replica_service.snapshot_replica(session, replica)
                snapshot_id = str((snap.status or {}).get("last_snapshot_id") or "")
                rolled.append((snap.id, snapshot_id))
                op.child(
                    "replica.rollout",
                    snap.id,
                    "Captured pre-rollout snapshot",
                    snapshot_id=snapshot_id,
                )
                try:
                    await replica_service.restart_replica(session, snap)
                    op.child("replica.rollout", snap.id, "Restarted replica after snapshot")
                except lxd_service.LXDOperationError as exc:
                    op.step_warning(
                        "replica.rollout",
                        "Replica restart failed; attempting rollback",
                        replica_id=snap.id,
                        error_type=type(exc).__name__,
                        error=exc.detail,
                    )
                    rollback_failures = 0
                    for restore_replica_id, restore_snapshot_id in reversed(rolled):
                        rollback_row = await session.get(Replica, restore_replica_id)
                        if rollback_row is None:
                            rollback_failures += 1
                            op.child(
                                "replica.rollback",
                                restore_replica_id,
                                "Skipped rollback; replica row missing",
                            )
                            continue
                        try:
                            await replica_service.restore_replica(
                                session,
                                rollback_row,
                                restore_snapshot_id or None,
                            )
                            op.child(
                                "replica.rollback",
                                restore_replica_id,
                                "Restored replica after failed rollout",
                                snapshot_id=restore_snapshot_id,
                            )
                        except lxd_service.LXDOperationError as restore_exc:
                            rollback_failures += 1
                            op.child(
                                "replica.rollback",
                                restore_replica_id,
                                "Replica rollback failed",
                                error_type=type(restore_exc).__name__,
                                error=restore_exc.detail,
                            )
                    await record_event(
                        session,
                        event_id=str(uuid4()),
                        category="services",
                        name="service.rollout.failed",
                        level="ERROR",
                        fields={
                            "service_id": service.id,
                            "replica_id": snap.id,
                            "rollback_failures": rollback_failures,
                        },
                    )
                    await session.commit()
                    raise lxd_service.LXDOperationError(
                        "service.rollout",
                        f"replica {snap.id} restart failed; rollback_failures={rollback_failures}",
                    ) from exc
        elif _settings.lxd_enabled:
            op.step("replica.rollout", "No replicas to roll out")
        else:
            op.step("lxd.skip", "Skipped rollout execution (LXD disabled)")

        service.generation += 1
        spec = dict(service.spec or {})
        spec["rollout_requested_at"] = datetime.now(timezone.utc).isoformat()
        spec["rollout_replica_count"] = len(replicas)
        service.spec = spec
        op.step("spec.mark", "Marked rollout request", generation=service.generation)
        await record_event(
            session,
            event_id=str(uuid4()),
            category="services",
            name="service.rollout",
            level="INFO",
            fields={"service_id": service.id, "generation": service.generation},
        )
        op.step("event.record", "Recorded rollout event")
        await session.commit()
        await session.refresh(service)
        op.step("db.commit", "Committed rollout request")
        return service


async def rollback_service(
    session: AsyncSession,
    service: Service,
    target_generation: Optional[int],
) -> Service:
    async with _logger.operation(
        "service.rollback",
        "Requesting service rollback",
        service_id=service.id,
        current_generation=service.generation,
        target_generation=target_generation or 0,
    ) as op:
        result = await session.execute(
            select(Replica).where(Replica.service_id == service.id).order_by(Replica.id.asc())
        )
        replicas = list(result.scalars().all())
        op.step("replica.select", "Fetched service replicas", count=len(replicas))

        if _settings.lxd_enabled and replicas:
            restore_failures = 0
            restored = 0
            for replica in replicas:
                snapshot_id = str((replica.status or {}).get("last_snapshot_id") or "")
                try:
                    await replica_service.restore_replica(session, replica, snapshot_id or None)
                    restored += 1
                    op.child(
                        "replica.restore",
                        replica.id,
                        "Restored replica snapshot",
                        snapshot_id=snapshot_id,
                    )
                except lxd_service.LXDOperationError as exc:
                    restore_failures += 1
                    op.child(
                        "replica.restore",
                        replica.id,
                        "Replica restore failed",
                        error_type=type(exc).__name__,
                        error=exc.detail,
                    )
            if restore_failures:
                await record_event(
                    session,
                    event_id=str(uuid4()),
                    category="services",
                    name="service.rollback.failed",
                    level="ERROR",
                    fields={
                        "service_id": service.id,
                        "restore_failures": restore_failures,
                        "replicas_total": len(replicas),
                    },
                )
                await session.commit()
                raise lxd_service.LXDOperationError(
                    "service.rollback",
                    f"failed to restore {restore_failures}/{len(replicas)} replicas",
                )
            op.step("replica.restore", "Restored replicas for rollback", restored=restored)
        elif _settings.lxd_enabled:
            op.step("replica.restore", "No replicas to roll back")
        else:
            op.step("lxd.skip", "Skipped rollback execution (LXD disabled)")

        if target_generation is not None and target_generation > 0:
            service.generation = target_generation
            op.step("generation.set", "Applied explicit rollback target", generation=service.generation)
        elif service.generation > 1:
            service.generation -= 1
            op.step("generation.decrement", "Rolled back one generation", generation=service.generation)
        else:
            op.step_warning("generation.boundary", "Service is already at minimum generation", generation=service.generation)

        spec = dict(service.spec or {})
        spec["rollback_requested_at"] = datetime.now(timezone.utc).isoformat()
        spec["rollback_replica_count"] = len(replicas)
        service.spec = spec
        await record_event(
            session,
            event_id=str(uuid4()),
            category="services",
            name="service.rollback",
            level="INFO",
            fields={"service_id": service.id, "generation": service.generation},
        )
        op.step("event.record", "Recorded rollback event", generation=service.generation)
        await session.commit()
        await session.refresh(service)
        op.step("db.commit", "Committed rollback request")
        return service


async def apply_pinned_placement(
    session: AsyncSession,
    service: Service,
) -> Service:
    async with _logger.operation(
        "service.pinned.apply",
        "Applying pinned replica placement",
        service_id=service.id,
    ) as op:
        spec = dict(service.spec or {})
        pinned, strict = _extract_pinned_placement(spec)
        op.step("spec.parse", "Parsed pinned placement", replicas=len(pinned), strict=strict)
        if not pinned:
            op.step("pinned.skip", "No pinned replicas defined in service spec")
            return service

        current = await replica_service.list_replicas_for_service(session, service.id)
        current_by_id = {row.id: row for row in current}
        desired_ids = {str(item["replica_id"]) for item in pinned}

        created = 0
        moved = 0
        updated = 0
        removed = 0

        for item in pinned:
            replica_id = str(item["replica_id"])
            node_id = str(item["node_id"])
            desired_state = str(item["desired_state"])
            status_map = dict(item["status"] if isinstance(item["status"], dict) else {})

            replica = current_by_id.get(replica_id)
            if replica is None:
                replica = await replica_service.create_replica(
                    session,
                    ReplicaCreate(
                        id=replica_id,
                        service_id=service.id,
                        node_id=node_id,
                        desired_state=desired_state,
                        status=status_map,
                    ),
                )
                current_by_id[replica_id] = replica
                created += 1
                op.child("pinned.apply", replica_id, "Created pinned replica", node_id=node_id)
                continue

            if replica.node_id != node_id:
                replica = await replica_service.move_replica(session, replica, node_id)
                current_by_id[replica_id] = replica
                moved += 1
                op.child("pinned.apply", replica_id, "Moved replica to pinned node", node_id=node_id)

            desired_patch: ReplicaUpdate | None = None
            patch_state = desired_state if replica.desired_state != desired_state else None
            patch_status = status_map if status_map else None
            if patch_state is not None or patch_status is not None:
                desired_patch = ReplicaUpdate(desired_state=patch_state, status=patch_status)
            if desired_patch is not None:
                replica = await replica_service.update_replica(session, replica, desired_patch)
                current_by_id[replica_id] = replica
                updated += 1
                op.child("pinned.apply", replica_id, "Updated pinned replica state")

        if strict:
            for replica in list(current_by_id.values()):
                if replica.id in desired_ids:
                    continue
                await replica_service.delete_replica(session, replica)
                removed += 1
                op.child("pinned.apply", replica.id, "Deleted replica not present in strict pinned spec")

        spec["pinned_last_applied_at"] = datetime.now(timezone.utc).isoformat()
        spec["pinned_applied_count"] = len(pinned)
        spec["pinned_strict_applied"] = strict
        service.spec = spec
        op.step(
            "spec.mark",
            "Updated pinned placement metadata",
            created=created,
            moved=moved,
            updated=updated,
            removed=removed,
        )

        await record_event(
            session,
            event_id=str(uuid4()),
            category="services",
            name="service.pinned.apply",
            level="INFO",
            fields={
                "service_id": service.id,
                "created": created,
                "moved": moved,
                "updated": updated,
                "removed": removed,
                "strict": strict,
            },
        )
        op.step("event.record", "Recorded pinned placement apply event")
        await session.commit()
        await session.refresh(service)
        op.step("db.commit", "Committed pinned placement apply")
        return service
