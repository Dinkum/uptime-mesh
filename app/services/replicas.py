from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.models.node import Node
from app.models.endpoint import Endpoint
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.replicas import ReplicaCreate, ReplicaUpdate
from app.services.events import record_event
from app.services import docker as docker_service
from app.services import lxd as lxd_service
from app.services.runtime_drivers import runtime_kind_for_spec

_logger = get_logger("services.replicas")
_settings = get_settings()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _container_name_for(replica: Replica, service: Service) -> str:
    status = replica.status if isinstance(replica.status, dict) else {}
    runtime_kind = runtime_kind_for_spec(service.spec or {})
    if runtime_kind == "docker":
        existing = status.get("docker_container_name")
        if isinstance(existing, str) and existing.strip():
            return existing.strip()
        return docker_service.container_name(service.name, replica.id)
    existing = status.get("lxd_container_name")
    if isinstance(existing, str) and existing.strip():
        return existing.strip()
    return lxd_service.container_name(service.name, replica.id)


async def _service_and_node(
    session: AsyncSession,
    *,
    service_id: str,
    node_id: str,
) -> tuple[Service, Node]:
    service = await session.get(Service, service_id)
    if service is None:
        raise lxd_service.LXDOperationError("replica.resolve", f"service not found: {service_id}")
    node = await session.get(Node, node_id)
    if node is None:
        raise lxd_service.LXDOperationError("replica.resolve", f"node not found: {node_id}")
    return service, node


def _merge_lxd_status(status: dict[str, object], **fields: object) -> dict[str, object]:
    merged = dict(status)
    merged.update(fields)
    return merged


def _merge_runtime_status(status: dict[str, object], **fields: object) -> dict[str, object]:
    merged = dict(status)
    merged.update(fields)
    return merged


async def _upsert_replica_endpoint(
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


async def list_replicas(session: AsyncSession, limit: int = 200) -> List[Replica]:
    result = await session.execute(select(Replica).limit(limit))
    return list(result.scalars().all())


async def get_replica(session: AsyncSession, replica_id: str) -> Optional[Replica]:
    result = await session.execute(select(Replica).where(Replica.id == replica_id))
    return result.scalar_one_or_none()


async def list_replicas_for_service(
    session: AsyncSession,
    service_id: str,
    limit: int = 1000,
) -> List[Replica]:
    result = await session.execute(
        select(Replica).where(Replica.service_id == service_id).limit(limit)
    )
    return list(result.scalars().all())


async def reconcile_runtime_intents(session: AsyncSession, *, limit: int = 200) -> int:
    result = await session.execute(select(Replica).limit(limit))
    replicas = list(result.scalars().all())
    changed = 0
    for replica in replicas:
        status = dict(replica.status or {})
        state = str(status.get("runtime_reconcile_state") or "").strip().lower()
        if state not in {"provisioning", "moving", "provision_failed", "move_cutover_failed"}:
            continue
        status["runtime_reconcile_state"] = "needs_reconcile"
        status["runtime_last_action"] = "startup.reconcile.flag"
        status["runtime_last_action_at"] = _utcnow_iso()
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.runtime_drift",
            level="WARNING",
            fields={
                "replica_id": replica.id,
                "service_id": replica.service_id,
                "previous_state": state,
            },
        )
        changed += 1
    if changed:
        await session.commit()
    return changed


async def create_replica(session: AsyncSession, payload: ReplicaCreate) -> Replica:
    async with _logger.operation(
        "replica.create",
        "Creating replica",
        replica_id=payload.id,
        service_id=payload.service_id,
        node_id=payload.node_id,
    ) as op:
        service, node = await _service_and_node(
            session,
            service_id=payload.service_id,
            node_id=payload.node_id,
        )
        status = dict(payload.status or {})
        runtime_kind = runtime_kind_for_spec(service.spec or {})
        status = _merge_runtime_status(
            status,
            runtime_kind=runtime_kind,
            runtime_reconcile_state="provisioning",
            runtime_last_action="create.claimed",
            runtime_last_action_at=_utcnow_iso(),
        )
        replica = Replica(
            id=payload.id,
            service_id=payload.service_id,
            node_id=payload.node_id,
            desired_state=payload.desired_state,
            status=status,
        )
        session.add(replica)
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.create.claimed",
            level="INFO",
            fields={
                "replica_id": payload.id,
                "service_id": payload.service_id,
                "node_id": payload.node_id,
                "lxd_enabled": _settings.lxd_enabled,
                "docker_enabled": _settings.docker_enabled,
                "runtime_kind": runtime_kind,
            },
        )
        await session.commit()
        await session.refresh(replica)
        op.step("db.claim", "Committed durable replica intent before runtime side effects")

        try:
            spec: lxd_service.LXDContainerSpec | None = None
            docker_spec: docker_service.DockerContainerSpec | None = None
            status = dict(replica.status or {})
            if runtime_kind == "docker":
                docker_spec = docker_service.build_container_spec(
                    service_name=service.name,
                    service_spec=service.spec or {},
                    replica_id=payload.id,
                    node=node,
                    desired_state=payload.desired_state,
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
                status = _merge_runtime_status(
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
                    docker_last_action_at=_utcnow_iso(),
                )
                await _upsert_replica_endpoint(
                    session,
                    replica_id=payload.id,
                    address=endpoint_address,
                    port=endpoint_port,
                    healthy=healthy,
                )
            elif _settings.lxd_enabled:
                spec = lxd_service.build_container_spec(
                    service_name=service.name,
                    service_spec=service.spec or {},
                    replica_id=payload.id,
                    node_name=node.name,
                    desired_state=payload.desired_state,
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
                status = _merge_lxd_status(
                    status,
                    runtime_kind="lxd",
                    runtime_reconcile_state="provisioned",
                    lxd_container_name=spec.name,
                    lxd_project=spec.project,
                    lxd_state=runtime_state,
                    lxd_last_error="",
                    lxd_last_action="create",
                    lxd_last_action_at=_utcnow_iso(),
                )
                op.step("lxd.ensure", "Ensured LXD container", state=runtime_state)
            else:
                status = _merge_lxd_status(
                    status,
                    runtime_kind=runtime_kind,
                    runtime_reconcile_state="provisioned",
                    lxd_last_action="create.skipped",
                    lxd_last_action_at=_utcnow_iso(),
                )
                op.step("runtime.skip", "Skipped runtime orchestration (disabled)")

            replica.status = status
            await record_event(
                session,
                event_id=str(uuid4()),
                category="replicas",
                name="replica.create",
                level="INFO",
                fields={
                    "replica_id": payload.id,
                    "service_id": payload.service_id,
                    "node_id": payload.node_id,
                    "runtime_kind": runtime_kind,
                },
            )
            await session.commit()
        except Exception as exc:
            await session.rollback()
            fresh = await session.get(Replica, payload.id)
            if fresh is not None:
                failed_status = _merge_runtime_status(
                    dict(fresh.status or {}),
                    runtime_reconcile_state="provision_failed",
                    runtime_last_error=f"{type(exc).__name__}: {exc}",
                    runtime_last_action="create.failed",
                    runtime_last_action_at=_utcnow_iso(),
                )
                fresh.status = failed_status
                await session.commit()
            raise
        await session.refresh(replica)
        _logger.info("replicas.create", "Created replica", replica_id=replica.id)
        return replica


async def update_replica(
    session: AsyncSession,
    replica: Replica,
    payload: ReplicaUpdate,
) -> Replica:
    changed = False
    status_map = dict(replica.status or {})
    if payload.desired_state is not None:
        replica.desired_state = payload.desired_state
        changed = True
        service = await session.get(Service, replica.service_id)
        if service is None:
            raise lxd_service.LXDOperationError(
                "replica.update",
                f"service not found: {replica.service_id}",
            )
        runtime_kind = runtime_kind_for_spec(service.spec or {})
        if runtime_kind == "docker" and _settings.docker_enabled:
            container_name = _container_name_for(replica, service)
            docker_host = str(status_map.get("docker_host") or "")
            desired = payload.desired_state.lower()
            if desired == "running":
                await docker_service.start_container(name=container_name, docker_host=docker_host)
                runtime_state = await docker_service.container_status(
                    name=container_name,
                    docker_host=docker_host,
                )
            elif desired in {"stopped", "stop"}:
                await docker_service.stop_container(name=container_name, docker_host=docker_host)
                runtime_state = "stopped"
            else:
                runtime_state = await docker_service.container_status(
                    name=container_name,
                    docker_host=docker_host,
                )
            status_map = _merge_runtime_status(
                status_map,
                runtime_kind="docker",
                docker_container_name=container_name,
                docker_state=runtime_state,
                docker_last_error="",
                docker_last_action="update.state",
                docker_last_action_at=_utcnow_iso(),
            )
        elif runtime_kind != "docker" and _settings.lxd_enabled:
            container_name = _container_name_for(replica, service)
            project = str(status_map.get("lxd_project") or _settings.lxd_project)
            desired = payload.desired_state.lower()
            if desired == "running":
                await lxd_service.start_container(name=container_name, project=project)
                runtime_state = "running"
            elif desired in {"stopped", "stop"}:
                await lxd_service.stop_container(name=container_name, project=project)
                runtime_state = "stopped"
            else:
                runtime_state = await lxd_service.container_status(
                    name=container_name,
                    project=project,
                )
            status_map = _merge_lxd_status(
                status_map,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="update.state",
                lxd_last_action_at=_utcnow_iso(),
            )
    if payload.status is not None:
        status_map = _merge_lxd_status(status_map, **payload.status)
        changed = True

    if changed:
        replica.status = status_map
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.update",
            level="INFO",
            fields={
                "replica_id": replica.id,
                "desired_state": replica.desired_state,
            },
        )

    await session.commit()
    await session.refresh(replica)
    return replica


async def move_replica(
    session: AsyncSession,
    replica: Replica,
    target_node_id: str,
) -> Replica:
    async with _logger.operation(
        "replica.move",
        "Moving replica",
        replica_id=replica.id,
        current_node_id=replica.node_id,
        target_node_id=target_node_id,
    ) as op:
        if replica.node_id == target_node_id:
            op.step("move.skip", "Replica already pinned to target node")
            return replica

        status = dict(replica.status or {})
        service, target_node = await _service_and_node(
            session,
            service_id=replica.service_id,
            node_id=target_node_id,
        )
        runtime_kind = runtime_kind_for_spec(service.spec or {})
        status = _merge_runtime_status(
            status,
            runtime_reconcile_state="moving",
            runtime_last_move_source_node=replica.node_id,
            runtime_last_move_target_node=target_node_id,
            runtime_last_action="move.claimed",
            runtime_last_action_at=_utcnow_iso(),
        )
        replica.status = status
        await session.commit()
        await session.refresh(replica)
        status = dict(replica.status or {})
        op.step("db.claim", "Committed durable replica move intent before runtime side effects")
        if runtime_kind == "docker" and _settings.docker_enabled:
            source_name = _container_name_for(replica, service)
            source_host = str(status.get("docker_host") or "")
            target_spec = docker_service.build_container_spec(
                service_name=service.name,
                service_spec=service.spec or {},
                replica_id=replica.id,
                node=target_node,
                desired_state=replica.desired_state,
            )
            op.step(
                "docker.move",
                "Recreating Docker replica on target node",
                source_container=source_name,
                target_container=target_spec.name,
                target_node=target_node.id,
            )
            await docker_service.ensure_container(target_spec)
            if source_host != target_spec.docker_host or source_name != target_spec.name:
                await docker_service.delete_container(name=source_name, docker_host=source_host)
            runtime_state = await docker_service.container_status(
                name=target_spec.name,
                docker_host=target_spec.docker_host,
            )
            endpoint_address, endpoint_port = docker_service.endpoint_for_container(
                node=target_node,
                spec=target_spec,
            )
            status = _merge_runtime_status(
                status,
                runtime_kind="docker",
                docker_container_name=target_spec.name,
                docker_image=target_spec.image,
                docker_host=target_spec.docker_host,
                docker_state=runtime_state,
                docker_endpoint_address=endpoint_address,
                docker_endpoint_port=endpoint_port,
                docker_last_move_source_node=replica.node_id,
                docker_last_move_target_node=target_node_id,
                docker_last_error="",
                docker_last_action="move.recreate",
                docker_last_action_at=_utcnow_iso(),
            )
            await _upsert_replica_endpoint(
                session,
                replica_id=replica.id,
                address=endpoint_address,
                port=endpoint_port,
                healthy=True,
            )
            op.step("docker.status", "Docker replica move complete", docker_state=runtime_state)
        elif runtime_kind != "docker" and _settings.lxd_enabled:
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            temp_name = f"{container_name}-mv-{uuid4().hex[:6]}"[:63].strip("-")
            source_exists = await lxd_service.container_exists(name=container_name, project=project)
            temp_created = False
            cutover_started = False
            cutover_recovered = False

            try:
                spec = lxd_service.build_container_spec(
                    service_name=service.name,
                    service_spec=service.spec or {},
                    replica_id=replica.id,
                    node_name=target_node.name,
                    desired_state=replica.desired_state,
                )
                staged_spec = replace(
                    spec,
                    name=temp_name,
                    project=project,
                    target_node=target_node.name,
                )
                op.step(
                    "lxd.stage.init",
                    "Creating staged target container",
                    source_container=container_name,
                    staged_container=temp_name,
                    project=project,
                    target_node=target_node.name,
                    source_exists=source_exists,
                )
                await lxd_service.ensure_container(staged_spec)
                temp_created = True
                staged_state = await lxd_service.container_status(name=temp_name, project=project)
                op.step(
                    "lxd.stage.health_gate",
                    "Staged target container passed health gate",
                    staged_container=temp_name,
                    staged_state=staged_state,
                )

                cutover_started = True
                if source_exists:
                    op.step(
                        "lxd.cutover.stop",
                        "Stopping and deleting source container before cutover",
                        source_container=container_name,
                    )
                    await lxd_service.delete_container(name=container_name, project=project)
                else:
                    op.step("lxd.cutover.source", "Source container missing; cutover continues")

                await lxd_service.rename_container(
                    source_name=temp_name,
                    target_name=container_name,
                    project=project,
                )
                op.step(
                    "lxd.cutover.rename",
                    "Renamed staged container to canonical name",
                    source_container=temp_name,
                    target_container=container_name,
                )
            except lxd_service.LXDOperationError as exc:
                if temp_created and cutover_started:
                    canonical_exists = await lxd_service.container_exists(
                        name=container_name,
                        project=project,
                    )
                    staged_exists = await lxd_service.container_exists(
                        name=temp_name,
                        project=project,
                    )
                    if staged_exists and not canonical_exists:
                        try:
                            await lxd_service.rename_container(
                                source_name=temp_name,
                                target_name=container_name,
                                project=project,
                            )
                            cutover_recovered = True
                            op.step_warning(
                                "lxd.cutover.recover",
                                "Completed staged rename after cutover failure",
                                staged_container=temp_name,
                                target_container=container_name,
                                original_error=exc.detail,
                            )
                        except lxd_service.LXDOperationError as recover_exc:
                            op.step_warning(
                                "lxd.cutover.recover",
                                "Failed to recover staged rename after cutover failure",
                                staged_container=temp_name,
                                target_container=container_name,
                                error_type=type(recover_exc).__name__,
                                error=recover_exc.detail,
                            )
                    elif canonical_exists:
                        cutover_recovered = True
                        op.step_warning(
                            "lxd.cutover.recover",
                            "Canonical container exists after cutover failure",
                            target_container=container_name,
                            staged_container=temp_name,
                            staged_exists=staged_exists,
                            original_error=exc.detail,
                        )
                    if not cutover_recovered:
                        replica.status = _merge_lxd_status(
                            status,
                            lxd_container_name=temp_name if staged_exists else container_name,
                            lxd_project=project,
                            lxd_target_node=target_node.name,
                            lxd_state="move_cutover_failed",
                            lxd_move_strategy="staged",
                            lxd_last_move_source_node=replica.node_id,
                            lxd_last_move_target_node=target_node_id,
                            lxd_last_error=exc.detail,
                            lxd_last_action="move.cutover_failed",
                            lxd_last_action_at=_utcnow_iso(),
                        )
                        await session.commit()
                if temp_created and not cutover_started:
                    try:
                        await lxd_service.delete_container(name=temp_name, project=project)
                        op.step(
                            "lxd.stage.cleanup",
                            "Deleted staged container after pre-cutover failure",
                            staged_container=temp_name,
                        )
                    except lxd_service.LXDOperationError as cleanup_exc:
                        op.step_warning(
                            "lxd.stage.cleanup",
                            "Failed to delete staged container after move failure",
                            staged_container=temp_name,
                            error_type=type(cleanup_exc).__name__,
                            error=cleanup_exc.detail,
                        )
                if not cutover_recovered:
                    raise

            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_target_node=target_node.name,
                lxd_state=runtime_state,
                lxd_move_strategy="staged",
                lxd_last_move_source_node=replica.node_id,
                lxd_last_move_target_node=target_node_id,
                lxd_last_error="",
                lxd_last_action="move.staged",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Staged move complete", lxd_state=runtime_state)
        else:
            op.step("runtime.skip", "Skipped runtime move (disabled)", runtime_kind=runtime_kind)
        replica.node_id = target_node_id
        status = _merge_runtime_status(
            status,
            runtime_reconcile_state="moved",
            runtime_last_action="move.completed",
            runtime_last_action_at=_utcnow_iso(),
        )
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.move",
            level="INFO",
            fields={
                "replica_id": replica.id,
                "target_node_id": target_node_id,
                "strategy": (
                    "docker_recreate"
                    if runtime_kind == "docker" and _settings.docker_enabled
                    else "staged" if runtime_kind != "docker" and _settings.lxd_enabled else "logical"
                ),
            },
        )
        op.step("event.record", "Recorded replica move event")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica move transaction")
        return replica


async def restart_replica(session: AsyncSession, replica: Replica) -> Replica:
    async with _logger.operation(
        "replica.restart",
        "Restarting replica",
        replica_id=replica.id,
    ) as op:
        status = dict(replica.status or {})
        status["last_restart_at"] = _utcnow_iso()
        service = await session.get(Service, replica.service_id)
        if service is None:
            raise lxd_service.LXDOperationError(
                "replica.restart",
                f"service not found: {replica.service_id}",
            )
        runtime_kind = runtime_kind_for_spec(service.spec or {})
        if runtime_kind == "docker" and _settings.docker_enabled:
            container_name = _container_name_for(replica, service)
            docker_host = str(status.get("docker_host") or "")
            op.step("docker.restart", "Restarting Docker container", container=container_name)
            await docker_service.restart_container(name=container_name, docker_host=docker_host)
            runtime_state = await docker_service.container_status(
                name=container_name,
                docker_host=docker_host,
            )
            status = _merge_runtime_status(
                status,
                runtime_kind="docker",
                docker_container_name=container_name,
                docker_state=runtime_state,
                docker_last_error="",
                docker_last_action="restart",
                docker_last_action_at=_utcnow_iso(),
            )
            op.step("docker.status", "Container restart complete", docker_state=runtime_state)
        elif runtime_kind != "docker" and _settings.lxd_enabled:
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            op.step("lxd.restart", "Restarting LXD container", container=container_name, project=project)
            await lxd_service.restart_container(name=container_name, project=project)
            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="restart",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Container restart complete", lxd_state=runtime_state)
        else:
            op.step("runtime.skip", "Skipped runtime restart (disabled)", runtime_kind=runtime_kind)
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.restart",
            level="INFO",
            fields={"replica_id": replica.id},
        )
        op.step("event.record", "Recorded replica restart event")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica restart transaction")
        return replica


async def snapshot_replica(session: AsyncSession, replica: Replica) -> Replica:
    async with _logger.operation(
        "replica.snapshot",
        "Snapshotting replica",
        replica_id=replica.id,
    ) as op:
        status = dict(replica.status or {})
        snapshot_id = datetime.now(timezone.utc).strftime("snap-%Y%m%d%H%M%S")
        status["last_snapshot_at"] = _utcnow_iso()
        status["last_snapshot_id"] = snapshot_id
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.snapshot",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            op.step(
                "lxd.snapshot",
                "Creating LXD snapshot",
                container=container_name,
                project=project,
                snapshot_id=snapshot_id,
            )
            await lxd_service.snapshot_container(
                name=container_name,
                project=project,
                snapshot=snapshot_id,
            )
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_last_error="",
                lxd_last_action="snapshot",
                lxd_last_action_at=_utcnow_iso(),
            )
        else:
            op.step("lxd.skip", "Skipped LXD snapshot (disabled)", snapshot_id=snapshot_id)
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.snapshot",
            level="INFO",
            fields={"replica_id": replica.id, "snapshot_id": snapshot_id},
        )
        op.step("event.record", "Recorded replica snapshot event", snapshot_id=snapshot_id)
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica snapshot transaction")
        return replica


async def restore_replica(
    session: AsyncSession,
    replica: Replica,
    snapshot_id: Optional[str],
) -> Replica:
    async with _logger.operation(
        "replica.restore",
        "Restoring replica from snapshot",
        replica_id=replica.id,
        snapshot_id=snapshot_id or "",
    ) as op:
        status = dict(replica.status or {})
        resolved_snapshot = snapshot_id or str(status.get("last_snapshot_id") or "")
        if _settings.lxd_enabled:
            service = await session.get(Service, replica.service_id)
            if service is None:
                raise lxd_service.LXDOperationError(
                    "replica.restore",
                    f"service not found: {replica.service_id}",
                )
            container_name = _container_name_for(replica, service)
            project = str(status.get("lxd_project") or _settings.lxd_project)
            if not resolved_snapshot:
                snapshots = await lxd_service.list_snapshots(name=container_name, project=project)
                op.step("lxd.snapshots", "Fetched container snapshots", count=len(snapshots))
                if snapshots:
                    resolved_snapshot = snapshots[-1]
                    op.step("snapshot.resolve", "Resolved latest snapshot", snapshot_id=resolved_snapshot)
            if not resolved_snapshot:
                raise lxd_service.LXDOperationError(
                    "replica.restore",
                    "no snapshot id provided and none available",
                )
            op.step(
                "lxd.restore",
                "Restoring LXD snapshot",
                container=container_name,
                project=project,
                snapshot_id=resolved_snapshot,
            )
            await lxd_service.restore_container(
                name=container_name,
                project=project,
                snapshot=resolved_snapshot,
            )
            runtime_state = await lxd_service.container_status(name=container_name, project=project)
            status = _merge_lxd_status(
                status,
                lxd_container_name=container_name,
                lxd_project=project,
                lxd_state=runtime_state,
                lxd_last_error="",
                lxd_last_action="restore",
                lxd_last_action_at=_utcnow_iso(),
            )
            op.step("lxd.status", "Container restore complete", lxd_state=runtime_state)
        else:
            op.step("lxd.skip", "Skipped LXD restore (disabled)")
        status["last_restore_at"] = _utcnow_iso()
        if resolved_snapshot:
            status["last_restore_snapshot_id"] = resolved_snapshot
        replica.status = status
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.restore",
            level="INFO",
            fields={"replica_id": replica.id, "snapshot_id": resolved_snapshot or ""},
        )
        op.step("event.record", "Recorded replica restore event", snapshot_id=resolved_snapshot or "")
        await session.commit()
        await session.refresh(replica)
        op.step("db.commit", "Committed replica restore transaction")
        return replica


async def delete_replica(session: AsyncSession, replica: Replica) -> None:
    replica_id = replica.id
    service_id = replica.service_id
    async with _logger.operation(
        "replica.delete",
        "Deleting replica",
        replica_id=replica_id,
        service_id=service_id,
    ) as op:
        service = await session.get(Service, replica.service_id)
        if service is None:
            raise lxd_service.LXDOperationError(
                "replica.delete",
                f"service not found: {replica.service_id}",
            )
        runtime_kind = runtime_kind_for_spec(service.spec or {})
        if runtime_kind == "docker" and _settings.docker_enabled:
            container_name = _container_name_for(replica, service)
            docker_host = str((replica.status or {}).get("docker_host") or "")
            op.step("docker.delete", "Deleting Docker container", container=container_name)
            await docker_service.delete_container(name=container_name, docker_host=docker_host)
        elif runtime_kind != "docker" and _settings.lxd_enabled:
            container_name = _container_name_for(replica, service)
            project = str((replica.status or {}).get("lxd_project") or _settings.lxd_project)
            op.step("lxd.delete", "Deleting LXD container", container=container_name, project=project)
            await lxd_service.delete_container(name=container_name, project=project)
        else:
            op.step("runtime.skip", "Skipped runtime delete (disabled)", runtime_kind=runtime_kind)
        await record_event(
            session,
            event_id=str(uuid4()),
            category="replicas",
            name="replica.delete",
            level="INFO",
            fields={"replica_id": replica_id, "service_id": service_id},
        )
        op.step("event.record", "Recorded replica delete event")
        endpoints = await session.execute(select(Endpoint).where(Endpoint.replica_id == replica_id))
        for endpoint in endpoints.scalars().all():
            await session.delete(endpoint)
        await session.delete(replica)
        try:
            await session.commit()
        except Exception as exc:
            await session.rollback()
            stale_replica = await session.get(Replica, replica_id)
            if stale_replica is not None:
                stale_replica.status = _merge_lxd_status(
                    dict(stale_replica.status or {}),
                    lxd_state="deleted",
                    lxd_last_error=f"DB delete commit failed after LXD delete: {type(exc).__name__}: {exc}",
                    lxd_last_action="delete.db_commit_failed",
                    lxd_last_action_at=_utcnow_iso(),
                )
                await session.commit()
            _logger.error(
                "replicas.delete.drift",
                "Replica DB delete failed after LXD container delete",
                replica_id=replica_id,
                service_id=service_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            raise
        op.step("db.commit", "Committed replica delete transaction")
        _logger.info("replicas.delete", "Deleted replica", replica_id=replica_id)
