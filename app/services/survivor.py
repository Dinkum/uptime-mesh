from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.endpoint import Endpoint
from app.models.node import Node
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.survivor import SurvivorFailureOut, SurvivorReportOut, SurvivorServiceOut
from app.services.runtime_drivers import desired_replicas_for_spec


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _node_online(node: Node, now: datetime) -> bool:
    lease_expires = _as_utc(node.lease_expires_at)
    heartbeat_at = _as_utc(node.heartbeat_at)
    if lease_expires and lease_expires > now:
        return True
    return bool(heartbeat_at and (now - heartbeat_at).total_seconds() <= 180)


def _replica_healthy(replica: Replica, endpoint_by_replica: dict[str, list[Endpoint]]) -> bool:
    status = replica.status if isinstance(replica.status, dict) else {}
    if replica.desired_state.lower() != "running":
        return False
    if status.get("healthy") is False:
        return False
    state = str(status.get("state") or status.get("update_state") or "").strip().lower()
    if state in {"failed", "error", "stalled", "crashloop"}:
        return False
    endpoints = endpoint_by_replica.get(replica.id, [])
    if endpoints:
        return any(endpoint.healthy for endpoint in endpoints)
    return True


def _service_capacity(service_spec: dict[str, Any], replica: Replica) -> float:
    status = replica.status if isinstance(replica.status, dict) else {}
    capacity = service_spec.get("capacity")
    capacity_map = capacity if isinstance(capacity, dict) else {}
    return _float_value(
        status.get("serving_capacity", capacity_map.get("per_replica", 1.0)),
        default=1.0,
    )


def _current_demand(service_spec: dict[str, Any]) -> float:
    capacity = service_spec.get("capacity")
    capacity_map = capacity if isinstance(capacity, dict) else {}
    return _float_value(capacity_map.get("current_demand", 1.0), default=1.0)


def _protection(service_spec: dict[str, Any]) -> str:
    availability = service_spec.get("availability")
    availability_map = availability if isinstance(availability, dict) else {}
    return str(availability_map.get("protection") or "best_effort").strip().lower() or "best_effort"


def build_survivor_row(
    *,
    service: Service,
    replicas: list[Replica],
    endpoint_by_replica: dict[str, list[Endpoint]],
    node_by_id: dict[str, Node],
    now: datetime,
) -> SurvivorServiceOut:
    service_spec = service.spec if isinstance(service.spec, dict) else {}
    protection = _protection(service_spec)
    desired_replicas = desired_replicas_for_spec(service_spec, default=len(replicas))
    min_survivors = 1 if protection in {"survive_one_failure", "protected"} else 0
    current_demand = _current_demand(service_spec)

    online_node_ids = {node.id for node in node_by_id.values() if _node_online(node, now)}
    healthy_replicas = [
        replica
        for replica in replicas
        if replica.node_id in online_node_ids and _replica_healthy(replica, endpoint_by_replica)
    ]
    healthy_nodes = {replica.node_id for replica in healthy_replicas}
    serving_capacity = sum(_service_capacity(service_spec, replica) for replica in healthy_replicas)

    failures: list[SurvivorFailureOut] = []
    warnings: list[str] = []
    recommended_actions: list[str] = []
    for node_id in sorted(online_node_ids):
        survivors = [replica for replica in healthy_replicas if replica.node_id != node_id]
        survivor_capacity = sum(_service_capacity(service_spec, replica) for replica in survivors)
        failures.append(
            SurvivorFailureOut(
                failure_domain=f"node:{node_id}",
                lost_node_id=node_id,
                healthy_replicas_after_loss=len(survivors),
                serving_capacity_after_loss=survivor_capacity,
                current_demand=current_demand,
                serving=len(survivors) >= max(min_survivors, 1),
                capacity_ok=survivor_capacity >= current_demand,
            )
        )

    if protection in {"survive_one_failure", "protected"} and desired_replicas < 2:
        warnings.append("Protected services need at least two replicas.")
        recommended_actions.append("Set scheduling.desired_replicas to at least 2.")
    if len(healthy_nodes) < min(2, desired_replicas) and protection in {"survive_one_failure", "protected"}:
        warnings.append("Healthy replicas are not spread across enough nodes.")
        recommended_actions.append("Reconcile scheduling with anti-affinity enabled.")
    if not healthy_replicas:
        warnings.append("No healthy serving replicas.")
        recommended_actions.append("Restore or recreate at least one replica.")
    elif serving_capacity < current_demand:
        warnings.append("Current healthy capacity is below declared demand.")
        recommended_actions.append("Add replicas or raise per-replica capacity.")

    failed_survivor_tests = [
        failure for failure in failures if not failure.serving or not failure.capacity_ok
    ]
    if not healthy_replicas:
        state = "user_impacting_incident"
    elif protection in {"survive_one_failure", "protected"} and failed_survivor_tests:
        state = "at_risk"
    elif warnings:
        state = "degraded_but_serving"
    else:
        state = "protected"

    return SurvivorServiceOut(
        service_id=service.id,
        service_name=service.name,
        protection=protection,
        state=state,
        desired_replicas=desired_replicas,
        total_replicas=len(replicas),
        healthy_replicas=len(healthy_replicas),
        healthy_nodes=len(healthy_nodes),
        current_demand=current_demand,
        serving_capacity=serving_capacity,
        min_survivors=min_survivors,
        failures=failures,
        warnings=warnings,
        recommended_actions=recommended_actions,
    )


async def build_survivor_report(session: AsyncSession, *, limit: int = 500) -> SurvivorReportOut:
    now = datetime.now(timezone.utc)
    services = list((await session.execute(select(Service).limit(limit))).scalars().all())
    service_ids = [service.id for service in services]
    replicas_by_service: dict[str, list[Replica]] = {service.id: [] for service in services}
    endpoint_by_replica: dict[str, list[Endpoint]] = {}
    if service_ids:
        replicas = list(
            (
                await session.execute(select(Replica).where(Replica.service_id.in_(service_ids)))
            ).scalars().all()
        )
        replica_ids = [replica.id for replica in replicas]
        for replica in replicas:
            replicas_by_service.setdefault(replica.service_id, []).append(replica)
        if replica_ids:
            endpoints = list(
                (
                    await session.execute(select(Endpoint).where(Endpoint.replica_id.in_(replica_ids)))
                ).scalars().all()
            )
            for endpoint in endpoints:
                endpoint_by_replica.setdefault(endpoint.replica_id, []).append(endpoint)
    nodes = list((await session.execute(select(Node))).scalars().all())
    node_by_id = {node.id: node for node in nodes}

    rows = [
        build_survivor_row(
            service=service,
            replicas=replicas_by_service.get(service.id, []),
            endpoint_by_replica=endpoint_by_replica,
            node_by_id=node_by_id,
            now=now,
        )
        for service in services
    ]
    return SurvivorReportOut(
        services=rows,
        protected=sum(1 for row in rows if row.state == "protected"),
        degraded=sum(1 for row in rows if row.state == "degraded_but_serving"),
        at_risk=sum(1 for row in rows if row.state == "at_risk"),
        incidents=sum(1 for row in rows if row.state == "user_impacting_incident"),
    )
