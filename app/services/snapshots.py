from __future__ import annotations

import hashlib
import asyncio
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List
from uuid import uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_sessionmaker
from app.logger import get_logger
from app.models.snapshot_run import SnapshotRun
from app.schemas.snapshots import SnapshotRunCreate
from app.services import etcd as etcd_service
from app.services.events import record_event

_logger = get_logger("services.snapshots")
_settings = get_settings()
_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class SnapshotRestoreRejected(RuntimeError):
    def __init__(self, reason: str, *, status_code: int = 409) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot_path(snapshot_id: str) -> Path:
    clean_id = snapshot_id.strip()
    if not _ARTIFACT_ID_RE.fullmatch(clean_id):
        raise ValueError("snapshot id must be a safe artifact slug")
    base = Path(_settings.etcd_snapshot_dir).resolve()
    path = (base / f"{clean_id}.db").resolve()
    if not path.is_relative_to(base):
        raise ValueError("snapshot path escapes snapshot directory")
    return path


def _snapshot_restore_dir(snapshot_id: str, timestamp: str) -> Path:
    clean_id = snapshot_id.strip()
    if not _ARTIFACT_ID_RE.fullmatch(clean_id):
        raise ValueError("snapshot id must be a safe artifact slug")
    base = (Path(_settings.etcd_snapshot_dir) / "restore").resolve()
    path = (base / clean_id / timestamp).resolve()
    if not path.is_relative_to(base):
        raise ValueError("snapshot restore path escapes snapshot directory")
    return path


def _snapshot_temp_path(final_path: Path) -> Path:
    return final_path.with_name(f".{final_path.name}.{uuid4().hex}.tmp")


def snapshot_artifact_path(snapshot: SnapshotRun) -> Path:
    if not snapshot.location:
        raise ValueError("snapshot has no artifact location")
    base = Path(_settings.etcd_snapshot_dir).resolve()
    path = Path(snapshot.location).resolve()
    if not path.is_relative_to(base):
        raise ValueError("snapshot artifact path escapes snapshot directory")
    return path


def validate_snapshot_artifact(snapshot: SnapshotRun) -> Path:
    if snapshot.status not in {"completed", "restored"}:
        raise ValueError(f"snapshot status '{snapshot.status}' is not downloadable")
    path = snapshot_artifact_path(snapshot)
    if not path.exists():
        raise FileNotFoundError(f"snapshot artifact file is missing: {path}")
    ok, expected, actual = _validate_snapshot_integrity(path)
    if not ok:
        raise ValueError(f"snapshot checksum mismatch (expected={expected}, actual={actual})")
    return path


def _snapshot_sha_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sha256")


def _snapshot_meta_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta.json")


def _compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_snapshot_checksum(path: Path) -> str:
    sha_path = _snapshot_sha_path(path)
    if not sha_path.exists():
        return ""
    raw = sha_path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return ""
    return raw.split()[0]


def _write_snapshot_sidecars(path: Path, *, requested_by: str) -> dict[str, str | int]:
    checksum = _compute_sha256(path)
    size_bytes = path.stat().st_size
    created_at = _utcnow_iso()

    _snapshot_sha_path(path).write_text(f"{checksum}  {path.name}\n", encoding="utf-8")
    meta = {
        "snapshot_file": path.name,
        "snapshot_path": str(path),
        "checksum_sha256": checksum,
        "size_bytes": size_bytes,
        "created_at": created_at,
        "requested_by": requested_by,
        "etcd_endpoints": _settings.etcd_endpoints,
    }
    _snapshot_meta_path(path).write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return meta


def _validate_snapshot_integrity(path: Path) -> tuple[bool, str, str]:
    expected = _read_snapshot_checksum(path)
    if not expected:
        return True, "", ""
    actual = _compute_sha256(path)
    if actual == expected:
        return True, expected, actual
    return False, expected, actual


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


async def claim_snapshot_job(
    session: AsyncSession,
    snapshot_id: str,
    *,
    stale_after_seconds: int | None = None,
) -> SnapshotRun | None:
    claimable = [SnapshotRun.status == "pending"]
    if stale_after_seconds is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
        claimable.append(and_(SnapshotRun.status == "running", SnapshotRun.updated_at < cutoff))
    result = await session.execute(
        update(SnapshotRun)
        .where(SnapshotRun.id == snapshot_id, or_(*claimable))
        .values(status="running", error=None)
    )
    if int(getattr(result, "rowcount", 0) or 0) != 1:
        await session.rollback()
        return None
    await session.commit()
    return await get_snapshot(session, snapshot_id)


async def request_snapshot(session: AsyncSession, payload: SnapshotRunCreate) -> SnapshotRun:
    snapshot_id = payload.id or str(uuid4())
    requested_by = payload.requested_by or "api.request"
    async with _logger.operation(
        "snapshot.request",
        "Requesting snapshot run",
        snapshot_id=snapshot_id,
        requested_by=requested_by,
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
            fields={"snapshot_id": snapshot.id, "requested_by": requested_by},
        )
        op.step("event.record", "Recorded snapshot request event")
        await session.commit()
        await session.refresh(snapshot)
        op.step("db.commit", "Committed snapshot request transaction")
        return snapshot


async def execute_snapshot(session: AsyncSession, snapshot: SnapshotRun) -> SnapshotRun:
    requested_by = snapshot.requested_by or "api.request"
    async with _logger.operation(
        "snapshot.execute",
        "Executing snapshot run",
        snapshot_id=snapshot.id,
        requested_by=requested_by,
    ) as op:
        if not (_settings.etcd_enabled and _settings.etcd_endpoints.strip()):
            snapshot.status = "skipped"
            snapshot.error = "etcd is disabled or unconfigured"
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="snapshot.skipped",
                level="WARNING",
                fields={"snapshot_id": snapshot.id, "reason": snapshot.error},
            )
            await session.commit()
            await session.refresh(snapshot)
            op.step_warning("snapshot.skip", "Skipped snapshot execution", reason=snapshot.error)
            return snapshot

        location = _snapshot_path(snapshot.id)
        temp_location = _snapshot_temp_path(location)
        snapshot.status = "running"
        snapshot.error = None
        snapshot.location = str(location)
        await session.commit()
        await session.refresh(snapshot)
        op.step("state.running", "Marked snapshot as running", location=str(location))

        try:
            await etcd_service.snapshot_save(path=str(temp_location))
            await asyncio.to_thread(os.replace, temp_location, location)
            meta = await asyncio.to_thread(
                _write_snapshot_sidecars,
                location,
                requested_by=requested_by,
            )
            snapshot.status = "completed"
            snapshot.error = None
            snapshot.location = str(location)
            await asyncio.to_thread(
                etcd_service.prune_old_snapshots,
                directory=_settings.etcd_snapshot_dir,
                keep=_settings.etcd_snapshot_retention,
            )
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="snapshot.completed",
                level="INFO",
                fields={
                    "snapshot_id": snapshot.id,
                    "location": str(location),
                    "checksum_sha256": str(meta["checksum_sha256"]),
                    "size_bytes": int(meta["size_bytes"]),
                },
            )
            op.step(
                "snapshot.save",
                "Saved etcd snapshot",
                location=str(location),
                checksum_sha256=str(meta["checksum_sha256"]),
                size_bytes=int(meta["size_bytes"]),
            )
        except Exception as exc:  # noqa: BLE001
            if temp_location.exists():
                try:
                    temp_location.unlink()
                except OSError:
                    pass
            snapshot.status = "failed"
            snapshot.error = f"{type(exc).__name__}: {exc}"
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="snapshot.failed",
                level="ERROR",
                fields={
                    "snapshot_id": snapshot.id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            op.step_warning(
                "snapshot.save",
                "Failed to save etcd snapshot",
                error_type=type(exc).__name__,
                error=str(exc),
            )
        await session.commit()
        await session.refresh(snapshot)
        op.step("db.commit", "Committed snapshot execution state", status=snapshot.status)

        _logger.info(
            "snapshots.create",
            "Requested snapshot",
            snapshot_id=snapshot.id,
            status=snapshot.status,
            location=snapshot.location or "",
        )
        return snapshot


async def create_snapshot(session: AsyncSession, payload: SnapshotRunCreate) -> SnapshotRun:
    snapshot = await request_snapshot(session, payload)
    claimed = await claim_snapshot_job(session, snapshot.id)
    if claimed is None:
        return snapshot
    return await execute_snapshot(session, claimed)


async def run_snapshot_job(snapshot_id: str) -> None:
    sessionmaker = get_sessionmaker(_settings.database_url)
    async with sessionmaker() as session:
        snapshot = await claim_snapshot_job(session, snapshot_id)
        if snapshot is None:
            _logger.warning(
                "snapshots.job.skip",
                "Snapshot job skipped because row is missing or already claimed",
                snapshot_id=snapshot_id,
            )
            return
        await execute_snapshot(session, snapshot)


async def recover_snapshot_jobs(
    session: AsyncSession,
    *,
    stale_after_seconds: int,
    limit: int = 5,
) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
    result = await session.execute(
        select(SnapshotRun)
        .where(
            or_(
                SnapshotRun.status == "pending",
                and_(SnapshotRun.status == "running", SnapshotRun.updated_at < cutoff),
            )
        )
        .order_by(SnapshotRun.created_at.asc())
        .limit(limit)
    )
    jobs = list(result.scalars().all())
    for snapshot in jobs:
        _logger.warning(
            "snapshots.job.recover",
            "Recovering persisted snapshot job",
            snapshot_id=snapshot.id,
            status=snapshot.status,
        )
        claimed = await claim_snapshot_job(
            session,
            snapshot.id,
            stale_after_seconds=stale_after_seconds,
        )
        if claimed is None:
            continue
        await execute_snapshot(session, claimed)
    return len(jobs)


async def restore_snapshot(session: AsyncSession, snapshot: SnapshotRun) -> SnapshotRun:
    async with _logger.operation(
        "snapshot.restore",
        "Restoring etcd snapshot",
        snapshot_id=snapshot.id,
    ) as op:
        if not (_settings.etcd_enabled and _settings.etcd_endpoints.strip()):
            await _record_restore_rejected(session, snapshot, "etcd is disabled or unconfigured")
            raise SnapshotRestoreRejected("etcd is disabled or unconfigured", status_code=503)

        if snapshot.status not in {"completed", "restored"}:
            reason = f"snapshot status '{snapshot.status}' is not restorable"
            await _record_restore_rejected(session, snapshot, reason)
            raise SnapshotRestoreRejected(reason)

        try:
            source_path = snapshot_artifact_path(snapshot)
        except ValueError as exc:
            await _record_restore_rejected(session, snapshot, str(exc))
            raise SnapshotRestoreRejected(str(exc)) from exc
        if not source_path.exists():
            reason = f"snapshot file does not exist: {source_path}"
            await _record_restore_rejected(session, snapshot, reason)
            raise SnapshotRestoreRejected(reason) from None

        ok, expected, actual = await asyncio.to_thread(_validate_snapshot_integrity, source_path)
        if not ok:
            reason = f"snapshot checksum mismatch (expected={expected}, actual={actual})"
            await _record_restore_rejected(session, snapshot, reason)
            raise SnapshotRestoreRejected(reason)
        if expected:
            op.step("checksum.verify", "Verified snapshot checksum", checksum_sha256=expected)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        try:
            restore_dir = _snapshot_restore_dir(snapshot.id, timestamp)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        restore_dir.mkdir(parents=True, exist_ok=True)

        restore_manifest = {
            "snapshot_id": snapshot.id,
            "source_snapshot": str(source_path),
            "restore_output_dir": str(restore_dir),
            "started_at": _utcnow_iso(),
            "requested_by": "api.restore",
        }
        (restore_dir / "restore.manifest.json").write_text(
            json.dumps(restore_manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        try:
            await etcd_service.restore_snapshot(path=str(source_path), output_dir=str(restore_dir))
            snapshot.status = "restored"
            snapshot.error = None
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="snapshot.restored",
                level="INFO",
                fields={
                    "snapshot_id": snapshot.id,
                    "source": str(source_path),
                    "restore_dir": str(restore_dir),
                },
            )
            op.step("snapshot.restore.run", "Executed etcd snapshot restore", output_dir=str(restore_dir))
        except Exception as exc:  # noqa: BLE001
            snapshot.status = "restore_failed"
            snapshot.error = f"{type(exc).__name__}: {exc}"
            await record_event(
                session,
                event_id=str(uuid4()),
                category="etcd",
                name="snapshot.restore_failed",
                level="ERROR",
                fields={
                    "snapshot_id": snapshot.id,
                    "source": str(source_path),
                    "restore_dir": str(restore_dir),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
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


async def _record_restore_rejected(
    session: AsyncSession,
    snapshot: SnapshotRun,
    reason: str,
) -> None:
    await record_event(
        session,
        event_id=str(uuid4()),
        category="etcd",
        name="snapshot.restore_rejected",
        level="WARNING",
        fields={"snapshot_id": snapshot.id, "reason": reason},
    )
    await session.commit()
