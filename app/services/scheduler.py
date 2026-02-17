from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.node import Node
from app.models.replica import Replica
from app.schemas.replicas import ReplicaCreate, ReplicaUpdate
from app.schemas.scheduler import SchedulerActionOut, SchedulerBulkResultOut, SchedulerResultOut
from app.services import events as event_service
from app.services import nodes as node_service
from app.services import replicas as replica_service
from app.services import services as service_service


@dataclass(frozen=True)
class SchedulingPolicy:
    desired_replicas: int
    node_selector: Dict[str, str]
    anti_affinity: bool
    reschedule_unhealthy: bool
    max_surge: int
    max_unavailable: int


def _to_int(value: object, default: int, minimum: int = 0) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(minimum, parsed)


def _extract_policy(spec: Dict[str, object], current_replicas: int) -> SchedulingPolicy:
    scheduling = spec.get("scheduling")
    scheduling_map = scheduling if isinstance(scheduling, dict) else {}

    rolling_update = spec.get("rolling_update")
    rolling_map = rolling_update if isinstance(rolling_update, dict) else {}

    selector = scheduling_map.get("node_selector")
    selector_map: Dict[str, str] = {}
    if isinstance(selector, dict):
        selector_map = {str(key): str(value) for key, value in selector.items()}

    desired = scheduling_map.get("desired_replicas", spec.get("replicas_desired", current_replicas))
    desired_replicas = _to_int(desired, current_replicas, minimum=0)

    anti_affinity = bool(scheduling_map.get("anti_affinity", True))
    reschedule_unhealthy = bool(scheduling_map.get("reschedule_unhealthy", True))

    max_surge = _to_int(rolling_map.get("max_surge", 1), 1, minimum=0)
    max_unavailable = _to_int(rolling_map.get("max_unavailable", 0), 0, minimum=0)

    return SchedulingPolicy(
        desired_replicas=desired_replicas,
        node_selector=selector_map,
        anti_affinity=anti_affinity,
        reschedule_unhealthy=reschedule_unhealthy,
        max_surge=max_surge,
        max_unavailable=max_unavailable,
    )


def _node_is_eligible(node: Node, selector: Dict[str, str]) -> bool:
    status = dict(node.status or {})
    if status.get("schedulable") is False:
        return False
    if status.get("draining") is True:
        return False
    if status.get("ready") is False:
        return False

    labels = dict(node.labels or {})
    for key, expected_value in selector.items():
        if key == "role":
            if expected_value not in list(node.roles or []):
                return False
            continue

        if key == "node_id":
            if node.id != expected_value:
                return False
            continue

        if labels.get(key) != expected_value:
            return False

    return True


def _replica_is_unhealthy(replica: Replica, node: Optional[Node], policy: SchedulingPolicy) -> bool:
    if not policy.reschedule_unhealthy:
        return False

    if node is None:
        return True

    if not _node_is_eligible(node, policy.node_selector):
        return True

    status = dict(replica.status or {})
    if status.get("healthy") is False:
        return True

    state = str(status.get("state", "")).lower().strip()
    return state in {"failed", "crashloop", "degraded"}


def _choose_target_node(
    eligible_nodes: List[Node],
    counts: Dict[str, int],
    anti_affinity: bool,
    exclude_node_id: Optional[str] = None,
) -> Optional[Node]:
    candidates = [node for node in eligible_nodes if node.id != exclude_node_id]
    if not candidates:
        candidates = eligible_nodes

    if not candidates:
        return None

    if anti_affinity:
        zero_replica_nodes = [node for node in candidates if counts.get(node.id, 0) == 0]
        if zero_replica_nodes:
            candidates = zero_replica_nodes

    return sorted(candidates, key=lambda node: (counts.get(node.id, 0), node.id))[0]


def _delete_rank(replica: Replica, counts: Dict[str, int]) -> tuple[int, int, datetime]:
    status = dict(replica.status or {})
    unhealthy_score = 1 if status.get("healthy") is False else 0
    updated_at = replica.updated_at
    return (counts.get(replica.node_id, 0), unhealthy_score, updated_at)


async def reconcile_service(
    session: AsyncSession,
    service_id: str,
    dry_run: bool = False,
) -> SchedulerResultOut:
    service = await service_service.get_service(session, service_id)
    if service is None:
        raise ValueError(f"Service not found: {service_id}")

    replicas = await replica_service.list_replicas_for_service(session, service_id)
    nodes = await node_service.list_nodes(session, limit=1000)

    spec = dict(service.spec or {})
    policy = _extract_policy(spec, current_replicas=len(replicas))

    node_by_id = {node.id: node for node in nodes}
    eligible_nodes = [node for node in nodes if _node_is_eligible(node, policy.node_selector)]

    warnings: List[str] = []
    actions: List[SchedulerActionOut] = []

    if not eligible_nodes:
        warnings.append("No eligible nodes available for scheduler policy.")

    replica_counts: Dict[str, int] = {}
    for replica in replicas:
        replica_counts[replica.node_id] = replica_counts.get(replica.node_id, 0) + 1

    for eligible_node in eligible_nodes:
        replica_counts.setdefault(eligible_node.id, 0)

    for replica in list(replicas):
        node = node_by_id.get(replica.node_id)
        if not _replica_is_unhealthy(replica, node, policy):
            continue

        target_node = _choose_target_node(
            eligible_nodes=eligible_nodes,
            counts=replica_counts,
            anti_affinity=policy.anti_affinity,
            exclude_node_id=replica.node_id,
        )

        if target_node is None:
            warnings.append(f"Replica {replica.id} is unhealthy but no target node is available.")
            continue

        if target_node.id == replica.node_id:
            warnings.append(
                f"Replica {replica.id} stayed on node {replica.node_id}; no better target."
            )
            continue

        source_node_id = replica.node_id
        if not dry_run:
            replica = await replica_service.move_replica(session, replica, target_node.id)

        replica_counts[source_node_id] = max(0, replica_counts.get(source_node_id, 0) - 1)
        replica_counts[target_node.id] = replica_counts.get(target_node.id, 0) + 1
        replica.node_id = target_node.id

        actions.append(
            SchedulerActionOut(
                action="move_unhealthy",
                service_id=service.id,
                replica_id=replica.id,
                source_node_id=source_node_id,
                target_node_id=target_node.id,
                detail="Rescheduled unhealthy replica",
            )
        )

    actual_replicas = len(replicas)

    while actual_replicas < policy.desired_replicas:
        target_node = _choose_target_node(
            eligible_nodes=eligible_nodes,
            counts=replica_counts,
            anti_affinity=policy.anti_affinity,
        )

        if target_node is None:
            warnings.append("Unable to scale up: no eligible nodes.")
            break

        replica_id = f"{service.id}-replica-{uuid4().hex[:8]}"
        replica_status = {
            "healthy": True,
            "managed_by": "scheduler",
            "applied_generation": service.generation,
        }

        if not dry_run:
            created_replica = await replica_service.create_replica(
                session,
                ReplicaCreate(
                    id=replica_id,
                    service_id=service.id,
                    node_id=target_node.id,
                    desired_state="running",
                    status=replica_status,
                ),
            )
            replicas.append(created_replica)

        replica_counts[target_node.id] = replica_counts.get(target_node.id, 0) + 1
        actual_replicas += 1

        actions.append(
            SchedulerActionOut(
                action="scale_up",
                service_id=service.id,
                replica_id=replica_id,
                target_node_id=target_node.id,
                detail="Created replica to satisfy desired count",
            )
        )

    while actual_replicas > policy.desired_replicas and replicas:
        candidate = sorted(
            replicas, key=lambda replica: _delete_rank(replica, replica_counts), reverse=True
        )[0]

        if not dry_run:
            await replica_service.delete_replica(session, candidate)

        replicas = [replica for replica in replicas if replica.id != candidate.id]
        replica_counts[candidate.node_id] = max(0, replica_counts.get(candidate.node_id, 0) - 1)
        actual_replicas -= 1

        actions.append(
            SchedulerActionOut(
                action="scale_down",
                service_id=service.id,
                replica_id=candidate.id,
                source_node_id=candidate.node_id,
                detail="Removed extra replica",
            )
        )

    rolling_window = max(1, policy.max_surge + policy.max_unavailable)
    outdated_replicas = [
        replica
        for replica in replicas
        if _to_int(dict(replica.status or {}).get("applied_generation"), 0) != service.generation
    ]

    for replica in outdated_replicas[:rolling_window]:
        status = dict(replica.status or {})
        status["desired_generation"] = service.generation
        status["update_state"] = "pending"

        if not dry_run:
            replica = await replica_service.update_replica(
                session,
                replica,
                ReplicaUpdate(status=status),
            )

        replica.status = status
        actions.append(
            SchedulerActionOut(
                action="queue_rolling_update",
                service_id=service.id,
                replica_id=replica.id,
                source_node_id=replica.node_id,
                detail="Queued replica for rolling update",
            )
        )

    generated_at = datetime.now(timezone.utc)
    result = SchedulerResultOut(
        service_id=service.id,
        desired_replicas=policy.desired_replicas,
        actual_replicas=actual_replicas,
        eligible_nodes=len(eligible_nodes),
        dry_run=dry_run,
        warnings=warnings,
        actions=actions,
        generated_at=generated_at,
    )

    if not dry_run:
        await event_service.record_event(
            session,
            event_id=str(uuid4()),
            category="scheduler",
            name="scheduler.reconcile",
            level="INFO",
            fields={
                "service_id": service.id,
                "desired_replicas": result.desired_replicas,
                "actual_replicas": result.actual_replicas,
                "action_count": len(result.actions),
                "warning_count": len(result.warnings),
            },
        )
        await session.commit()

    return result


async def reconcile_all_services(
    session: AsyncSession,
    dry_run: bool = False,
    limit: int = 200,
) -> SchedulerBulkResultOut:
    services = await service_service.list_services(session, limit=limit)
    results: List[SchedulerResultOut] = []

    for service in services:
        try:
            result = await reconcile_service(session, service.id, dry_run=dry_run)
        except ValueError as exc:
            result = SchedulerResultOut(
                service_id=service.id,
                desired_replicas=0,
                actual_replicas=0,
                eligible_nodes=0,
                dry_run=dry_run,
                warnings=[str(exc)],
                actions=[],
                generated_at=datetime.now(timezone.utc),
            )
        results.append(result)

    return SchedulerBulkResultOut(
        dry_run=dry_run,
        generated_at=datetime.now(timezone.utc),
        results=results,
    )
