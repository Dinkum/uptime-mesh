from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models.endpoint import Endpoint
from app.models.replica import Replica
from app.models.service import Service


async def build_runtime_inventory(session: AsyncSession, settings: Settings) -> dict[str, Any]:
    services = list((await session.execute(select(Service))).scalars().all())
    replicas = list((await session.execute(select(Replica))).scalars().all())
    endpoints = list((await session.execute(select(Endpoint))).scalars().all())

    managed_runtime = []
    needs_reconcile = []
    for replica in replicas:
        status = replica.status if isinstance(replica.status, dict) else {}
        runtime_kind = str(status.get("runtime_kind") or "unknown")
        state = str(status.get("runtime_reconcile_state") or "")
        row = {
            "type": "replica",
            "id": replica.id,
            "service_id": replica.service_id,
            "node_id": replica.node_id,
            "runtime": runtime_kind,
            "state": state or str(status.get("docker_state") or status.get("lxd_state") or "unknown"),
        }
        managed_runtime.append(row)
        if state in {"needs_reconcile", "provision_failed", "move_cutover_failed", "provisioning", "moving"}:
            needs_reconcile.append(
                {
                    **row,
                    "actions": ["repair_reference", "delete_runtime", "ignore"],
                }
            )

    generated_files = []
    for label, raw_path in (
        ("gateway_config", settings.runtime_gateway_config_path),
        ("gateway_candidate", settings.runtime_gateway_candidate_path),
        ("discovery_zone", settings.runtime_discovery_zone_path),
        ("discovery_corefile", settings.runtime_discovery_corefile_path),
        ("monitoring_config", settings.runtime_monitoring_prometheus_config_path),
    ):
        path = Path(raw_path)
        generated_files.append(
            {
                "id": label,
                "path": str(path),
                "exists": path.exists(),
                "stale": False,
                "actions": ["delete", "ignore"] if path.exists() else [],
            }
        )

    return {
        "counts": {
            "services": len(services),
            "replicas": len(replicas),
            "endpoints": len(endpoints),
            "managed_runtime": len(managed_runtime),
            "needs_reconcile": len(needs_reconcile),
            "generated_files": len(generated_files),
        },
        "managed_runtime": managed_runtime,
        "needs_reconcile": needs_reconcile,
        "generated_files": generated_files,
    }
