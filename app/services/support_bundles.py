from __future__ import annotations

import asyncio
import json
import platform
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List
from uuid import uuid4

from sqlalchemy import and_, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_sessionmaker
from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.models.node import Node
from app.models.replica import Replica
from app.models.router_assignment import RouterAssignment
from app.models.service import Service
from app.models.support_bundle import SupportBundle
from app.schemas.support_bundles import SupportBundleCreate
from app.services import cluster_settings as cluster_settings_service
from app.services import etcd as etcd_service
from app.services.events import record_event
from app.validation import artifact_id, path_under

_logger = get_logger("services.support_bundles")
_settings = get_settings()
_SENSITIVE_KEY_PARTS = ("secret", "token", "password", "private_key", "auth_cookie", "signing_key")
_BUNDLE_ROW_LIMIT = 2000
_LOG_TAIL_BYTES = 1024 * 1024


async def list_support_bundles(session: AsyncSession, limit: int = 50) -> List[SupportBundle]:
    async with _logger.operation(
        "support_bundle.list",
        "Listing support bundle requests",
        limit=limit,
    ) as op:
        result = await session.execute(
            select(SupportBundle).order_by(SupportBundle.created_at.desc()).limit(limit)
        )
        rows = list(result.scalars().all())
        op.step("db.select", "Fetched support bundle requests", count=len(rows))
        return rows


async def get_support_bundle(session: AsyncSession, bundle_id: str) -> SupportBundle | None:
    result = await session.execute(select(SupportBundle).where(SupportBundle.id == bundle_id))
    return result.scalar_one_or_none()


async def claim_support_bundle_job(
    session: AsyncSession,
    bundle_id: str,
    *,
    stale_after_seconds: int | None = None,
) -> SupportBundle | None:
    claimable = [SupportBundle.status == "pending"]
    if stale_after_seconds is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
        claimable.append(and_(SupportBundle.status == "running", SupportBundle.updated_at < cutoff))
    result = await session.execute(
        update(SupportBundle)
        .where(SupportBundle.id == bundle_id, or_(*claimable))
        .values(status="running", error=None)
    )
    if int(getattr(result, "rowcount", 0) or 0) != 1:
        await session.rollback()
        return None
    await session.commit()
    return await get_support_bundle(session, bundle_id)


async def create_support_bundle(
    session: AsyncSession, payload: SupportBundleCreate
) -> SupportBundle:
    bundle_id = payload.id or str(uuid4())
    async with _logger.operation(
        "support_bundle.request",
        "Requesting support bundle",
        bundle_id=bundle_id,
        requested_by=payload.requested_by,
    ) as op:
        bundle = SupportBundle(
            id=bundle_id,
            status="pending",
            requested_by=payload.requested_by,
        )
        session.add(bundle)
        op.step("db.insert", "Prepared support bundle row")
        await record_event(
            session,
            event_id=str(uuid4()),
            category="support",
            name="support_bundle.requested",
            level="INFO",
            fields={"bundle_id": bundle.id, "requested_by": payload.requested_by},
        )
        op.step("event.record", "Recorded support bundle request event")
        await session.commit()
        await session.refresh(bundle)
        op.step("db.commit", "Committed support bundle request transaction")
        return bundle


async def create_support_bundle_during_incident(
    session: AsyncSession, payload: SupportBundleCreate
) -> SupportBundle:
    bundle_id = payload.id or str(uuid4())
    async with _logger.operation(
        "support_bundle.request_incident",
        "Requesting support bundle during incident",
        bundle_id=bundle_id,
        requested_by=payload.requested_by,
    ) as op:
        try:
            await session.execute(
                insert(SupportBundle).values(
                    id=bundle_id,
                    status="pending",
                    requested_by=payload.requested_by,
                )
            )
            await record_event(
                session,
                event_id=str(uuid4()),
                category="support",
                name="support_bundle.requested",
                level="INFO",
                fields={"bundle_id": bundle_id, "requested_by": payload.requested_by},
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        op.step("db.commit", "Committed support bundle request transaction")
        bundle = await get_support_bundle(session, bundle_id)
        if bundle is None:
            raise RuntimeError("Support bundle request disappeared after commit")
        return bundle


async def execute_support_bundle(session: AsyncSession, bundle: SupportBundle) -> SupportBundle:
    async with _logger.operation(
        "support_bundle.execute",
        "Executing support bundle request",
        bundle_id=bundle.id,
        requested_by=bundle.requested_by,
    ) as op:
        bundle.status = "running"
        bundle.error = None
        await session.commit()
        await session.refresh(bundle)
        op.step("state.running", "Marked support bundle as running")
        try:
            output_path = await _generate_support_bundle(session, bundle.id)
            bundle.status = "completed"
            bundle.path = output_path
            bundle.error = None
            await record_event(
                session,
                event_id=str(uuid4()),
                category="support",
                name="support_bundle.completed",
                level="INFO",
                fields={"bundle_id": bundle.id, "path": output_path},
            )
            op.step("bundle.generate", "Generated support bundle artifact", path=output_path)
        except Exception as exc:  # noqa: BLE001
            bundle.status = "failed"
            bundle.error = f"{type(exc).__name__}: {exc}"
            await record_event(
                session,
                event_id=str(uuid4()),
                category="support",
                name="support_bundle.failed",
                level="ERROR",
                fields={
                    "bundle_id": bundle.id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            op.step_warning(
                "bundle.generate",
                "Failed to generate support bundle",
                error_type=type(exc).__name__,
                error=str(exc),
            )
        await session.commit()
        await session.refresh(bundle)
        op.step("db.commit", "Committed support bundle execution state", status=bundle.status)
        _logger.info(
            "support_bundles.create",
            "Requested support bundle",
            bundle_id=bundle.id,
            status=bundle.status,
        )
        return bundle


async def run_support_bundle_job(bundle_id: str) -> None:
    sessionmaker = get_sessionmaker(_settings.database_url)
    async with sessionmaker() as session:
        bundle = await claim_support_bundle_job(session, bundle_id)
        if bundle is None:
            _logger.warning(
                "support_bundles.job.skip",
                "Support bundle job skipped because row is missing or already claimed",
                bundle_id=bundle_id,
            )
            return
        await execute_support_bundle(session, bundle)


async def recover_support_bundle_jobs(
    session: AsyncSession,
    *,
    stale_after_seconds: int,
    limit: int = 5,
) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)
    result = await session.execute(
        select(SupportBundle)
        .where(
            or_(
                SupportBundle.status == "pending",
                and_(SupportBundle.status == "running", SupportBundle.updated_at < cutoff),
            )
        )
        .order_by(SupportBundle.created_at.asc())
        .limit(limit)
    )
    jobs = list(result.scalars().all())
    for bundle in jobs:
        _logger.warning(
            "support_bundles.job.recover",
            "Recovering persisted support bundle job",
            bundle_id=bundle.id,
            status=bundle.status,
        )
        claimed = await claim_support_bundle_job(
            session,
            bundle.id,
            stale_after_seconds=stale_after_seconds,
        )
        if claimed is None:
            continue
        await execute_support_bundle(session, claimed)
    return len(jobs)


def _row_dict(row: object) -> dict[str, object]:
    if row is None:
        return {}
    raw = dict(vars(row))
    raw.pop("_sa_instance_state", None)
    for key, value in list(raw.items()):
        if isinstance(value, datetime):
            raw[key] = value.astimezone(timezone.utc).isoformat()
    return raw


def _read_log_tail(path: str, max_lines: int = 2000) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    with file_path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - _LOG_TAIL_BYTES))
        raw = handle.read()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines) + ("\n" if lines else "")


def _looks_sensitive(key: str) -> bool:
    lowered = key.strip().lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _sanitize_obj(value: object, *, key_hint: str = "") -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, child in value.items():
            key_name = str(key)
            if _looks_sensitive(key_name):
                redacted[key_name] = "<redacted>"
            else:
                redacted[key_name] = _sanitize_obj(child, key_hint=key_name)
        return redacted
    if isinstance(value, list):
        return [_sanitize_obj(item, key_hint=key_hint) for item in value]
    if _looks_sensitive(key_hint):
        return "<redacted>"
    return value


def _render_restore_playbook() -> str:
    lines = [
        "# etcd Break-Glass Restore Playbook",
        "",
        "1. Stop etcd on all core nodes.",
        "2. Pick a seed node and restore from snapshot:",
        "   etcdctl snapshot restore <snapshot.db> --data-dir <restore-dir>",
        "3. Reconfigure and restart seed etcd with restored data-dir.",
        "4. Re-add remaining members to reform quorum.",
        "5. Verify endpoint health and member list before resuming writes.",
        "",
        "Notes:",
        "- Restoring snapshot data rewinds control-plane state to snapshot time.",
        "- Validate node certs, join tokens, and runtime config after restore.",
        "",
    ]
    return "\n".join(lines)


def _snapshot_inventory() -> list[dict[str, object]]:
    snapshot_dir = Path(_settings.etcd_snapshot_dir)
    if not snapshot_dir.exists():
        return []
    files = sorted(
        (item for item in snapshot_dir.glob("*.db") if item.is_file()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    rows: list[dict[str, object]] = []
    for item in files:
        stat = item.stat()
        rows.append(
            {
                "name": item.name,
                "path": str(item),
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        )
    return rows


def _cleanup_work_dir(work_dir: Path) -> None:
    for item in sorted(work_dir.rglob("*"), reverse=True):
        try:
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                item.rmdir()
        except OSError:
            continue
    try:
        work_dir.rmdir()
    except OSError:
        pass


def _write_support_bundle_files(
    *,
    work_dir: Path,
    archive_path: Path,
    bundle_id: str,
    manifest: dict[str, object],
    state: object,
    etcd_details: dict[str, object],
) -> str:
    (work_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (work_dir / "cluster_state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (work_dir / "etcd_state.json").write_text(
        json.dumps(etcd_details, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (work_dir / "etcd_snapshots.json").write_text(
        json.dumps({"snapshots": _snapshot_inventory()}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (work_dir / "app.log.tail").write_text(_read_log_tail(_settings.log_file), encoding="utf-8")
    agent_log_tail = _read_log_tail(getattr(_settings, "agent_log_file", "data/logs/agent.log"))
    (work_dir / "agent.log.tail").write_text(agent_log_tail, encoding="utf-8")
    (work_dir / "restore_playbook.md").write_text(_render_restore_playbook(), encoding="utf-8")

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(work_dir, arcname=bundle_id)
    return str(archive_path)


def _sanitize_cluster_settings_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    sanitized: list[dict[str, object]] = []
    for row in rows:
        key = str(row.get("key", ""))
        clean = dict(row)
        if key in cluster_settings_service.SENSITIVE_CLUSTER_SETTINGS or (
            key and _looks_sensitive(key)
        ):
            clean["value"] = "<redacted>"
        sanitized.append(clean)
    return sanitized


def _artifact_work_dir(base_dir: Path, bundle_id: str) -> Path:
    clean_id = artifact_id(bundle_id, field_name="support bundle id")
    base = base_dir.resolve()
    return path_under(base, base / f"{clean_id}.tmp", field_name="support bundle path")


def _artifact_archive_path(base_dir: Path, bundle_id: str) -> Path:
    clean_id = artifact_id(bundle_id, field_name="support bundle id")
    base = base_dir.resolve()
    return path_under(base, base / f"{clean_id}.tar.gz", field_name="support bundle archive path")


def support_bundle_artifact_path(bundle: SupportBundle) -> Path:
    if not bundle.path:
        raise ValueError("support bundle has no artifact path")
    base = Path(_settings.support_bundle_dir).resolve()
    return path_under(base, Path(bundle.path), field_name="support bundle artifact path")


async def _generate_support_bundle(session: AsyncSession, bundle_id: str) -> str:
    out_dir = Path(_settings.support_bundle_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = _artifact_work_dir(out_dir, bundle_id)
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        nodes = list((await session.execute(select(Node).order_by(Node.id).limit(_BUNDLE_ROW_LIMIT))).scalars().all())
        services = list((await session.execute(select(Service).order_by(Service.id).limit(_BUNDLE_ROW_LIMIT))).scalars().all())
        replicas = list((await session.execute(select(Replica).order_by(Replica.id).limit(_BUNDLE_ROW_LIMIT))).scalars().all())
        endpoints = list((await session.execute(select(Endpoint).order_by(Endpoint.id).limit(_BUNDLE_ROW_LIMIT))).scalars().all())
        assignments = list(
            (
                await session.execute(
                    select(RouterAssignment).order_by(RouterAssignment.id).limit(_BUNDLE_ROW_LIMIT)
                )
            )
            .scalars()
            .all()
        )
        settings_rows = list((await session.execute(select(ClusterSetting))).scalars().all())
        events = list((await session.execute(select(Event).order_by(Event.created_at.desc()).limit(500))).scalars().all())

        manifest = {
            "bundle_id": bundle_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": _settings.app_version,
            "manifest_version": _settings.app_manifest_version,
            "channel": _settings.app_release_channel,
            "env": _settings.app_env,
            "host": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
            },
            "counts": {
                "nodes": len(nodes),
                "services": len(services),
                "replicas": len(replicas),
                "endpoints": len(endpoints),
                "router_assignments": len(assignments),
                "cluster_settings": len(settings_rows),
                "events": len(events),
            },
            "limits": {
                "max_rows_per_table": _BUNDLE_ROW_LIMIT,
                "max_log_tail_bytes": _LOG_TAIL_BYTES,
                "max_log_tail_lines": 2000,
                "max_events": 500,
            },
        }
        cluster_settings_rows = _sanitize_cluster_settings_rows([_row_dict(item) for item in settings_rows])
        state = _sanitize_obj(
            {
                "nodes": [_row_dict(item) for item in nodes],
                "services": [_row_dict(item) for item in services],
                "replicas": [_row_dict(item) for item in replicas],
                "endpoints": [_row_dict(item) for item in endpoints],
                "router_assignments": [_row_dict(item) for item in assignments],
                "cluster_settings": cluster_settings_rows,
                "events": [_row_dict(item) for item in events],
            }
        )

        etcd_details = {
            "enabled": bool(_settings.etcd_enabled),
            "configured": bool(_settings.etcd_endpoints.strip()),
            "endpoints": _settings.etcd_endpoints,
            "health": [],
            "members": [],
            "error": "",
        }
        if _settings.etcd_enabled and _settings.etcd_endpoints.strip():
            try:
                health = await etcd_service.endpoint_health()
                members = await etcd_service.member_list()
                etcd_details["health"] = [
                    {
                        "endpoint": item.endpoint,
                        "healthy": item.healthy,
                        "error": item.error,
                        "took_seconds": item.took_seconds,
                    }
                    for item in health
                ]
                etcd_details["members"] = [
                    {
                        "member_id": item.member_id,
                        "name": item.name,
                        "peer_urls": item.peer_urls,
                        "client_urls": item.client_urls,
                        "is_learner": item.is_learner,
                    }
                    for item in members
                ]
            except Exception as exc:  # noqa: BLE001
                etcd_details["error"] = f"{type(exc).__name__}: {exc}"

        archive_path = _artifact_archive_path(out_dir, bundle_id)
        return await asyncio.to_thread(
            _write_support_bundle_files,
            work_dir=work_dir,
            archive_path=archive_path,
            bundle_id=bundle_id,
            manifest=manifest,
            state=state,
            etcd_details=etcd_details,
        )
    finally:
        await asyncio.to_thread(_cleanup_work_dir, work_dir)
