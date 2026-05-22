from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.formatting import as_utc, format_timestamp, safe_int
from app.services import replicas as replica_service
from app.services import scheduler as scheduler_service
from app.services import service_state as service_state_service
from app.services import services as service_service
from app.services import survivor as survivor_service


async def build_workloads_context(session: AsyncSession, *, subtab: str) -> dict[str, Any]:
    services = await service_service.list_services(session, limit=2000)
    now = datetime.now(timezone.utc)
    replicas = []
    if subtab in {"services", "replicas", "rollouts", "survivor", "state"}:
        replicas = await replica_service.list_replicas(session, limit=2000)
    rollout_rows = (
        service_service.build_rollout_rows(services, replicas, now=now)
        if subtab in {"services", "rollouts"}
        else []
    )
    stalled_rollouts = sum(1 for row in rollout_rows if row["state_key"] == "stalled")
    error_rollouts = sum(1 for row in rollout_rows if row["state_key"] == "error")
    service_name_by_id = {str(service.id): str(service.name) for service in services}
    service_generation_by_id = {
        str(service.id): int(getattr(service, "generation", 0) or 0) for service in services
    }
    replica_rows: list[dict[str, Any]] = []
    if subtab in {"replicas", "rollouts"}:
        for replica in replicas:
            status = replica.status if isinstance(replica.status, dict) else {}
            service_id = str(replica.service_id)
            current_generation = service_generation_by_id.get(service_id, 0)
            applied_generation = safe_int(str(status.get("applied_generation", "0")), default=0)
            update_state = str(status.get("update_state", "unknown")).strip().lower() or "unknown"
            replica_rows.append(
                {
                    "id": replica.id,
                    "service_id": service_id,
                    "service_name": service_name_by_id.get(service_id, service_id),
                    "node_id": replica.node_id,
                    "desired_state": replica.desired_state,
                    "update_state": update_state,
                    "applied_generation": applied_generation,
                    "target_generation": current_generation,
                    "updated_at": format_timestamp(as_utc(getattr(replica, "updated_at", None))),
                }
            )
    replica_rows.sort(key=lambda row: (row["service_name"].lower(), row["id"]))
    replica_rows_by_service: dict[str, list[dict[str, Any]]] = {}
    for row in replica_rows:
        replica_rows_by_service.setdefault(row["service_id"], []).append(row)

    rollout_watch_rows: list[dict[str, Any]] = []
    pending_states = {"pending", "queued", "in_progress", "updating", "rolling", "restarting"}
    failed_states = {"failed", "error", "stalled"}
    if subtab == "rollouts":
        for row in rollout_rows:
            blocking = []
            for replica in replica_rows_by_service.get(row["service_id"], []):
                is_outdated = replica["target_generation"] > replica["applied_generation"]
                is_non_healthy_state = (
                    replica["update_state"] in pending_states
                    or replica["update_state"] in failed_states
                )
                if is_outdated or is_non_healthy_state:
                    blocking.append(replica)
            if row["state_key"] == "complete" and not blocking:
                continue
            rollout_watch_rows.append(
                {
                    **row,
                    "blocking_count": len(blocking),
                    "blocking_preview": blocking[:6],
                }
            )
    severity_rank = {
        "error": 0,
        "stalled": 1,
        "rolling": 2,
        "outdated": 3,
        "no_replicas": 4,
        "complete": 5,
    }
    rollout_watch_rows.sort(
        key=lambda item: (
            severity_rank.get(item["state_key"], 9),
            item["progress_pct"],
            item["service_name"].lower(),
        )
    )
    rollout_watch_errors = sum(1 for row in rollout_watch_rows if row["state_key"] == "error")
    rollout_watch_stalled = sum(1 for row in rollout_watch_rows if row["state_key"] == "stalled")
    rollout_watch_active = sum(
        1 for row in rollout_watch_rows if row["state_key"] in {"rolling", "outdated"}
    )
    rollout_watch_blocked_replicas = sum(int(row["blocking_count"]) for row in rollout_watch_rows)
    plan = await scheduler_service.get_cached_plan(session) if subtab == "scheduler" else None
    survivor_report = await survivor_service.build_survivor_report(session) if subtab == "survivor" else None
    service_state_rows = (
        await service_state_service.list_service_states(session) if subtab == "state" else []
    )

    return {
        "workloads_subtab": subtab,
        "services": services,
        "rollout_rows": rollout_rows,
        "stalled_rollouts": stalled_rollouts,
        "error_rollouts": error_rollouts,
        "replica_rows": replica_rows,
        "rollout_watch_rows": rollout_watch_rows,
        "rollout_watch_errors": rollout_watch_errors,
        "rollout_watch_stalled": rollout_watch_stalled,
        "rollout_watch_active": rollout_watch_active,
        "rollout_watch_blocked_replicas": rollout_watch_blocked_replicas,
        "plan": plan,
        "survivor_report": survivor_report,
        "service_state_rows": service_state_rows,
    }
