from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.node import Node
from app.models.service import Service
from app.schemas.nodes import NodeCreate
from app.schemas.replicas import ReplicaCreate
from app.schemas.services import ServiceCreate
from app.services import nodes, replicas, services


async def seed_local_simulator(session: AsyncSession) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    created_nodes = 0
    for index in range(1, 4):
        node_id = f"sim-node-{index}"
        existing = await session.get(Node, node_id)
        if existing is None:
            node = await nodes.create_node(
                session,
                NodeCreate(
                    id=node_id,
                    name=f"Simulator Node {index}",
                    roles=["backend_server", "reverse_proxy"] if index == 1 else ["backend_server"],
                    labels={"simulator": "true", "zone": f"sim-{index}"},
                    mesh_ip=f"10.240.0.{index}",
                    status={"simulator": True, "schedulable": True, "ready": True},
                    api_endpoint=f"http://10.240.0.{index}:8010",
                ),
            )
            node.heartbeat_at = now
            node.lease_expires_at = now + timedelta(seconds=45)
            await session.commit()
            created_nodes += 1

    service_id = "sim-web"
    service = await session.get(Service, service_id)
    created_service = False
    if service is None:
        service = await services.create_service(
            session,
            ServiceCreate(
                id=service_id,
                name="Simulator Web",
                description="Local simulator workload",
                spec={
                    "type": "container",
                    "container": {"image": "ghcr.io/dinkum/simulator-web:1.0.0", "port": 8080},
                    "gateway": {"enabled": True, "host": "simulator.local", "path": "/"},
                    "availability": {"protection": "survive_one_failure"},
                    "scheduling": {"desired_replicas": 2, "anti_affinity": True},
                },
            ),
        )
        created_service = True

    created_replicas = 0
    for index in range(1, 3):
        replica_id = f"sim-web-{index}"
        if await replicas.get_replica(session, replica_id) is not None:
            continue
        await replicas.create_replica(
            session,
            ReplicaCreate(
                id=replica_id,
                service_id=service_id,
                node_id=f"sim-node-{index}",
                desired_state="running",
                status={"healthy": True, "applied_generation": service.generation, "simulator": True},
            ),
        )
        created_replicas += 1

    return {
        "created_nodes": created_nodes,
        "created_service": created_service,
        "created_replicas": created_replicas,
        "node_count": 3,
        "service_id": service_id,
    }
