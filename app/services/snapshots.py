from __future__ import annotations

from typing import List
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.snapshot_run import SnapshotRun
from app.schemas.snapshots import SnapshotRunCreate
from app.services.events import record_event

_logger = get_logger("services.snapshots")


async def list_snapshots(session: AsyncSession, limit: int = 50) -> List[SnapshotRun]:
    result = await session.execute(
        select(SnapshotRun).order_by(SnapshotRun.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def get_snapshot(session: AsyncSession, snapshot_id: str) -> SnapshotRun | None:
    result = await session.execute(select(SnapshotRun).where(SnapshotRun.id == snapshot_id))
    return result.scalar_one_or_none()


async def create_snapshot(session: AsyncSession, payload: SnapshotRunCreate) -> SnapshotRun:
    snapshot_id = payload.id or str(uuid4())
    snapshot = SnapshotRun(
        id=snapshot_id,
        status="pending",
        requested_by=payload.requested_by,
    )
    session.add(snapshot)
    await record_event(
        session,
        event_id=str(uuid4()),
        category="etcd",
        name="snapshot.requested",
        level="INFO",
        fields={"snapshot_id": snapshot.id, "requested_by": payload.requested_by},
    )
    await session.commit()
    await session.refresh(snapshot)
    _logger.info("snapshots.create", "Requested snapshot", snapshot_id=snapshot.id)
    return snapshot
