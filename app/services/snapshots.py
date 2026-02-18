from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
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


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot_path(snapshot_id: str) -> Path:
    return Path(_settings.etcd_snapshot_dir) / f"{snapshot_id}.db"


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


async def create_snapshot(session: AsyncSession, payload: SnapshotRunCreate) -> SnapshotRun:
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
        snapshot.status = "running"
        snapshot.error = None
        snapshot.location = str(location)
        await session.commit()
        await session.refresh(snapshot)
        op.step("state.running", "Marked snapshot as running", location=str(location))

        try:
            await etcd_service.snapshot_save(path=str(location))
            meta = _write_snapshot_sidecars(location, requested_by=requested_by)
            snapshot.status = "completed"
            snapshot.error = None
            snapshot.location = str(location)
            etcd_service.prune_old_snapshots(
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


async def restore_snapshot(session: AsyncSession, snapshot: SnapshotRun) -> SnapshotRun:
    async with _logger.operation(
        "snapshot.restore",
        "Restoring etcd snapshot",
        snapshot_id=snapshot.id,
    ) as op:
        if not (_settings.etcd_enabled and _settings.etcd_endpoints.strip()):
            raise RuntimeError("etcd is disabled or unconfigured")

        if snapshot.status not in {"completed", "restored"}:
            raise RuntimeError(f"snapshot status '{snapshot.status}' is not restorable")

        if not snapshot.location:
            raise RuntimeError("snapshot has no location to restore from")

        source_path = Path(snapshot.location)
        if not source_path.exists():
            raise RuntimeError(f"snapshot file does not exist: {source_path}")

        ok, expected, actual = _validate_snapshot_integrity(source_path)
        if not ok:
            raise RuntimeError(
                f"snapshot checksum mismatch (expected={expected}, actual={actual})"
            )
        if expected:
            op.step("checksum.verify", "Verified snapshot checksum", checksum_sha256=expected)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        restore_dir = Path(_settings.etcd_snapshot_dir) / "restore" / snapshot.id / timestamp
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
