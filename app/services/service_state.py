from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.endpoint import Endpoint
from app.models.node import Node
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.survivor import (
    ServiceStateActionOut,
    ServiceStateDesiredOut,
    ServiceStateObservedOut,
    ServiceStateOut,
)
from app.services.runtime_drivers import desired_replicas_for_spec, runtime_kind_for_spec
from app.services.survivor import build_survivor_row


def _healthy_endpoint_count(endpoints: list[Endpoint]) -> int:
    return sum(1 for endpoint in endpoints if endpoint.healthy)


async def build_service_state(
    session: AsyncSession,
    *,
    service: Service,
) -> ServiceStateOut:
    replicas = list(
        (
            await session.execute(select(Replica).where(Replica.service_id == service.id))
        ).scalars().all()
    )
    replica_ids = [replica.id for replica in replicas]
    endpoints: list[Endpoint] = []
    endpoint_by_replica: dict[str, list[Endpoint]] = {}
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
    spec = service.spec if isinstance(service.spec, dict) else {}
    survivor = build_survivor_row(
        service=service,
        replicas=replicas,
        endpoint_by_replica=endpoint_by_replica,
        node_by_id=node_by_id,
        now=datetime.now(timezone.utc),
    )
    gateway = spec.get("gateway")
    gateway_map = gateway if isinstance(gateway, dict) else {}
    actions: list[ServiceStateActionOut] = []
    for warning in survivor.warnings:
        actions.append(ServiceStateActionOut(action="survivor_warning", detail=warning))
    for recommendation in survivor.recommended_actions:
        actions.append(ServiceStateActionOut(action="recommended", detail=recommendation))
    for replica in replicas:
        status = replica.status if isinstance(replica.status, dict) else {}
        if int(status.get("applied_generation") or 0) < int(service.generation or 0):
            actions.append(
                ServiceStateActionOut(
                    action="queue_rollout",
                    detail="Replica has not applied the current service generation.",
                    replica_id=replica.id,
                    node_id=replica.node_id,
                )
            )

    return ServiceStateOut(
        service_id=service.id,
        service_name=service.name,
        desired=ServiceStateDesiredOut(
            runtime=runtime_kind_for_spec(spec),
            desired_replicas=desired_replicas_for_spec(spec, default=len(replicas)),
            gateway_enabled=bool(gateway_map.get("enabled", False)),
            protection=survivor.protection,
        ),
        observed=ServiceStateObservedOut(
            total_replicas=len(replicas),
            healthy_replicas=survivor.healthy_replicas,
            healthy_endpoints=_healthy_endpoint_count(endpoints),
            healthy_nodes=survivor.healthy_nodes,
            generation=int(service.generation or 0),
        ),
        survivor=survivor,
        actions=actions,
    )


async def list_service_states(session: AsyncSession, *, limit: int = 500) -> list[ServiceStateOut]:
    services = list((await session.execute(select(Service).limit(limit))).scalars().all())
    rows = []
    for service in services:
        rows.append(await build_service_state(session, service=service))
    return rows
