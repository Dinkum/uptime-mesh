from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import Operation
from app.models.endpoint import Endpoint
from app.models.node import Node
from app.models.replica import Replica
from app.models.service import Service
from app.services import docker as docker_service
from app.services import lxd as lxd_service

_settings = get_settings()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def merge_status(status: dict[str, object], **fields: object) -> dict[str, object]:
    merged = dict(status)
    merged.update(fields)
    return merged


async def upsert_replica_endpoint(
    session: AsyncSession,
    *,
    replica_id: str,
    address: str,
    port: int,
    healthy: bool,
) -> None:
    endpoint_id = f"{replica_id}-http"
    endpoint = await session.get(Endpoint, endpoint_id)
    if endpoint is None:
        session.add(
            Endpoint(
                id=endpoint_id,
                replica_id=replica_id,
                address=address,
                port=port,
                healthy=healthy,
            )
        )
        return
    endpoint.address = address
    endpoint.port = port
    endpoint.healthy = healthy
    endpoint.last_checked_at = datetime.now(timezone.utc)


async def provision_docker_replica(
    session: AsyncSession,
    op: Operation,
    *,
    service: Service,
    node: Node,
    replica: Replica,
    status: dict[str, object],
) -> dict[str, object]:
    docker_spec = docker_service.build_container_spec(
        service_name=service.name,
        service_spec=service.spec or {},
        replica_id=replica.id,
        node=node,
        desired_state=replica.desired_state,
    )
    endpoint_address, endpoint_port = docker_service.endpoint_for_container(
        node=node,
        spec=docker_spec,
    )
    if _settings.docker_enabled:
        op.step(
            "docker.spec",
            "Resolved Docker container spec",
            container=docker_spec.name,
            image=docker_spec.image,
            port=docker_spec.port,
            host_port=docker_spec.host_port,
        )
        await docker_service.ensure_container(docker_spec)
        runtime_state = await docker_service.container_status(
            name=docker_spec.name,
            docker_host=docker_spec.docker_host,
        )
        last_action = "create"
        healthy = True
        op.step("docker.ensure", "Ensured Docker container", state=runtime_state)
    else:
        runtime_state = ""
        last_action = "create.skipped"
        healthy = False
        op.step("docker.skip", "Skipped Docker orchestration (disabled)")

    await upsert_replica_endpoint(
        session,
        replica_id=replica.id,
        address=endpoint_address,
        port=endpoint_port,
        healthy=healthy,
    )
    return merge_status(
        status,
        runtime_kind="docker",
        runtime_reconcile_state="provisioned",
        docker_container_name=docker_spec.name,
        docker_image=docker_spec.image,
        docker_host=docker_spec.docker_host,
        docker_state=runtime_state,
        docker_endpoint_address=endpoint_address,
        docker_endpoint_port=endpoint_port,
        docker_last_error="",
        docker_last_action=last_action,
        docker_last_action_at=utcnow_iso(),
    )


async def provision_lxd_replica(
    op: Operation,
    *,
    service: Service,
    node: Node,
    replica: Replica,
    status: dict[str, object],
) -> dict[str, object]:
    spec = lxd_service.build_container_spec(
        service_name=service.name,
        service_spec=service.spec or {},
        replica_id=replica.id,
        node_name=node.name,
        desired_state=replica.desired_state,
    )
    op.step(
        "lxd.spec",
        "Resolved container spec",
        container=spec.name,
        project=spec.project,
        target_node=spec.target_node,
    )
    await lxd_service.ensure_container(spec)
    runtime_state = await lxd_service.container_status(
        name=spec.name,
        project=spec.project,
    )
    op.step("lxd.ensure", "Ensured LXD container", state=runtime_state)
    return merge_status(
        status,
        runtime_kind="lxd",
        runtime_reconcile_state="provisioned",
        lxd_container_name=spec.name,
        lxd_project=spec.project,
        lxd_state=runtime_state,
        lxd_last_error="",
        lxd_last_action="create",
        lxd_last_action_at=utcnow_iso(),
    )


def provision_logical_replica(
    op: Operation,
    *,
    runtime_kind: str,
    status: dict[str, object],
) -> dict[str, object]:
    op.step("runtime.skip", "Skipped runtime orchestration (disabled)")
    return merge_status(
        status,
        runtime_kind=runtime_kind,
        runtime_reconcile_state="provisioned",
        lxd_last_action="create.skipped",
        lxd_last_action_at=utcnow_iso(),
    )


async def mark_replica_create_failed(
    session: AsyncSession,
    *,
    replica_id: str,
    exc: Exception,
) -> None:
    await session.rollback()
    fresh = await session.get(Replica, replica_id)
    if fresh is None:
        return
    fresh.status = merge_status(
        dict(fresh.status or {}),
        runtime_reconcile_state="provision_failed",
        runtime_last_error=f"{type(exc).__name__}: {exc}",
        runtime_last_action="create.failed",
        runtime_last_action_at=utcnow_iso(),
    )
    await session.commit()
