from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
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
from app.services import etcd as etcd_service
from app.services.events import record_event

_logger = get_logger("services.support_bundles")
_settings = get_settings()


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

        try:
            output_path = await _generate_support_bundle(session, bundle.id)
            bundle.status = "completed"
            bundle.path = output_path
            bundle.error = None
            op.step("bundle.generate", "Generated support bundle artifact", path=output_path)
        except Exception as exc:  # noqa: BLE001
            bundle.status = "failed"
            bundle.error = f"{type(exc).__name__}: {exc}"
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
    text = file_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines) + ("\n" if lines else "")


async def _generate_support_bundle(session: AsyncSession, bundle_id: str) -> str:
    out_dir = Path(_settings.support_bundle_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / f"{bundle_id}.tmp"
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        nodes = list((await session.execute(select(Node))).scalars().all())
        services = list((await session.execute(select(Service))).scalars().all())
        replicas = list((await session.execute(select(Replica))).scalars().all())
        endpoints = list((await session.execute(select(Endpoint))).scalars().all())
        assignments = list((await session.execute(select(RouterAssignment))).scalars().all())
        settings_rows = list((await session.execute(select(ClusterSetting))).scalars().all())
        events = list((await session.execute(select(Event).order_by(Event.created_at.desc()).limit(500))).scalars().all())

        manifest = {
            "bundle_id": bundle_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": _settings.app_version,
            "manifest_version": _settings.app_manifest_version,
            "channel": _settings.app_release_channel,
            "env": _settings.app_env,
            "counts": {
                "nodes": len(nodes),
                "services": len(services),
                "replicas": len(replicas),
                "endpoints": len(endpoints),
                "router_assignments": len(assignments),
                "cluster_settings": len(settings_rows),
                "events": len(events),
            },
        }
        (work_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        state = {
            "nodes": [_row_dict(item) for item in nodes],
            "services": [_row_dict(item) for item in services],
            "replicas": [_row_dict(item) for item in replicas],
            "endpoints": [_row_dict(item) for item in endpoints],
            "router_assignments": [_row_dict(item) for item in assignments],
            "cluster_settings": [_row_dict(item) for item in settings_rows],
            "events": [_row_dict(item) for item in events],
        }
        (work_dir / "cluster_state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True),
            encoding="utf-8",
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
        (work_dir / "etcd_state.json").write_text(
            json.dumps(etcd_details, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        log_tail = _read_log_tail(_settings.log_file)
        (work_dir / "app.log.tail").write_text(log_tail, encoding="utf-8")

        archive_path = out_dir / f"{bundle_id}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(work_dir, arcname=bundle_id)
        return str(archive_path)
    finally:
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
