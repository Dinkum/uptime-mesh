from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.replica import Replica
from app.schemas.replicas import ReplicaCreate, ReplicaUpdate
from app.services.events import record_event

_logger = get_logger("services.replicas")


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
    replica = Replica(
        id=payload.id,
        service_id=payload.service_id,
        node_id=payload.node_id,
        desired_state=payload.desired_state,
        status=payload.status,
    )
    session.add(replica)
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.create",
        level="INFO",
        fields={"replica_id": payload.id, "service_id": payload.service_id},
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
    if payload.desired_state is not None:
        replica.desired_state = payload.desired_state
        changed = True
    if payload.status is not None:
        replica.status = payload.status
        changed = True

    if changed:
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.update",
            level="INFO",
            fields={"replica_id": replica.id},
        )

    await session.commit()
    await session.refresh(replica)
    return replica


async def move_replica(
    session: AsyncSession,
    replica: Replica,
    target_node_id: str,
) -> Replica:
    replica.node_id = target_node_id
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.move",
        level="INFO",
        fields={"replica_id": replica.id, "target_node_id": target_node_id},
    )
    await session.commit()
    await session.refresh(replica)
    return replica


async def restart_replica(session: AsyncSession, replica: Replica) -> Replica:
    status = dict(replica.status or {})
    status["last_restart_at"] = datetime.now(timezone.utc).isoformat()
    replica.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.restart",
        level="INFO",
        fields={"replica_id": replica.id},
    )
    await session.commit()
    await session.refresh(replica)
    return replica


async def snapshot_replica(session: AsyncSession, replica: Replica) -> Replica:
    status = dict(replica.status or {})
    status["last_snapshot_at"] = datetime.now(timezone.utc).isoformat()
    replica.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.snapshot",
        level="INFO",
        fields={"replica_id": replica.id},
    )
    await session.commit()
    await session.refresh(replica)
    return replica


async def restore_replica(
    session: AsyncSession,
    replica: Replica,
    snapshot_id: Optional[str],
) -> Replica:
    status = dict(replica.status or {})
    status["last_restore_at"] = datetime.now(timezone.utc).isoformat()
    if snapshot_id:
        status["last_restore_snapshot_id"] = snapshot_id
    replica.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.restore",
        level="INFO",
        fields={"replica_id": replica.id, "snapshot_id": snapshot_id},
    )
    await session.commit()
    await session.refresh(replica)
    return replica


async def delete_replica(session: AsyncSession, replica: Replica) -> None:
    replica_id = replica.id
    service_id = replica.service_id
    await record_event(
        session,
        event_id=str(uuid4()),
        category="replicas",
        name="replica.delete",
        level="INFO",
        fields={"replica_id": replica_id, "service_id": service_id},
    )
    await session.delete(replica)
    await session.commit()
    _logger.info("replicas.delete", "Deleted replica", replica_id=replica_id)
