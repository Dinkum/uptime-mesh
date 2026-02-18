from __future__ import annotations

import os
from typing import List
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.models.snapshot_run import SnapshotRun
from app.schemas.snapshots import SnapshotRunCreate
from app.services import etcd as etcd_service
from app.services.events import record_event

_logger = get_logger("services.snapshots")
_settings = get_settings()


async def list_snapshots(session: AsyncSession, limit: int = 50) -> List[SnapshotRun]:
    async with _logger.operation("snapshot.list", "Listing snapshot runs", limit=limit) as op:
        result = await session.execute(
            select(SnapshotRun).order_by(SnapshotRun.created_at.desc()).limit(limit)
        )
        rows = list(result.scalars().all())
        op.step("db.select", "Fetched snapshot runs", count=len(rows))
        return rows


async def get_snapshot(session: AsyncSession, snapshot_id: str) -> SnapshotRun | None:
    result = await session.execute(select(SnapshotRun).where(SnapshotRun.id == snapshot_id))
    return result.scalar_one_or_none()


async def create_snapshot(session: AsyncSession, payload: SnapshotRunCreate) -> SnapshotRun:
    snapshot_id = payload.id or str(uuid4())
    async with _logger.operation(
        "snapshot.request",
        "Requesting snapshot run",
        snapshot_id=snapshot_id,
        requested_by=payload.requested_by,
    ) as op:
        snapshot = SnapshotRun(
            id=snapshot_id,
            status="pending",
            requested_by=payload.requested_by,
        )
        session.add(snapshot)
        op.step("db.insert", "Prepared snapshot row")
        await record_event(
            session,
            event_id=str(uuid4()),
            category="etcd",
            name="snapshot.requested",
            level="INFO",
            fields={"snapshot_id": snapshot.id, "requested_by": payload.requested_by},
        )
        op.step("event.record", "Recorded snapshot request event")
        await session.commit()
        await session.refresh(snapshot)
        op.step("db.commit", "Committed snapshot request transaction")

        if _settings.etcd_enabled and _settings.etcd_endpoints.strip():
            location = os.path.join(_settings.etcd_snapshot_dir, f"{snapshot.id}.db")
            try:
                await etcd_service.snapshot_save(path=location)
                snapshot.status = "completed"
                snapshot.location = location
                snapshot.error = None
                etcd_service.prune_old_snapshots(
                    directory=_settings.etcd_snapshot_dir,
                    keep=_settings.etcd_snapshot_retention,
                )
                op.step("snapshot.save", "Saved etcd snapshot", location=location)
            except Exception as exc:  # noqa: BLE001
                snapshot.status = "failed"
                snapshot.error = f"{type(exc).__name__}: {exc}"
                op.step_warning(
                    "snapshot.save",
                    "Failed to save etcd snapshot",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            await session.commit()
            await session.refresh(snapshot)
            op.step("db.commit", "Committed snapshot execution state", status=snapshot.status)
        else:
            op.step("snapshot.skip", "Skipped snapshot execution (etcd disabled or unconfigured)")

        _logger.info(
            "snapshots.create",
            "Requested snapshot",
            snapshot_id=snapshot.id,
            status=snapshot.status,
            location=snapshot.location or "",
        )
        return snapshot


async def restore_snapshot(session: AsyncSession, snapshot: SnapshotRun) -> SnapshotRun:
    async with _logger.operation(
        "snapshot.restore",
        "Restoring etcd snapshot",
        snapshot_id=snapshot.id,
    ) as op:
        if not snapshot.location:
            raise RuntimeError("snapshot has no location to restore from")
        restore_dir = os.path.join(_settings.etcd_snapshot_dir, "restore", snapshot.id)
        os.makedirs(restore_dir, exist_ok=True)
        try:
            await etcd_service.restore_snapshot(path=snapshot.location, output_dir=restore_dir)
            snapshot.status = "restored"
            snapshot.error = None
            op.step("snapshot.restore.run", "Executed etcd snapshot restore", output_dir=restore_dir)
        except Exception as exc:  # noqa: BLE001
            snapshot.status = "restore_failed"
            snapshot.error = f"{type(exc).__name__}: {exc}"
            op.step_warning(
                "snapshot.restore.run",
                "Failed to restore snapshot",
                error_type=type(exc).__name__,
                error=str(exc),
            )
        await session.commit()
        await session.refresh(snapshot)
        op.step("db.commit", "Committed snapshot restore state", status=snapshot.status)
        return snapshot
