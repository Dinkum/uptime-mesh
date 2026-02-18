from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.node import Node
from app.schemas.nodes import NodeCreate, NodeUpdate
from app.services.events import record_event

_logger = get_logger("services.nodes")


async def list_nodes(session: AsyncSession, limit: int = 100) -> List[Node]:
    async with _logger.operation("node.list", "Listing nodes", limit=limit) as op:
        result = await session.execute(select(Node).limit(limit))
        rows = list(result.scalars().all())
        op.step("db.select", "Fetched nodes", count=len(rows))
        return rows


async def get_node(session: AsyncSession, node_id: str) -> Optional[Node]:
    result = await session.execute(select(Node).where(Node.id == node_id))
    return result.scalar_one_or_none()


async def get_node_by_name(session: AsyncSession, name: str) -> Optional[Node]:
    result = await session.execute(select(Node).where(Node.name == name))
    return result.scalar_one_or_none()


async def create_node(session: AsyncSession, payload: NodeCreate) -> Node:
    async with _logger.operation(
        "node.create",
        "Creating node",
        node_id=payload.id,
        name=payload.name,
    ) as op:
        node = Node(
            id=payload.id,
            name=payload.name,
            roles=payload.roles,
            labels=payload.labels,
            mesh_ip=payload.mesh_ip,
            status=payload.status,
            api_endpoint=payload.api_endpoint,
        )
        session.add(node)
        op.step("db.insert", "Prepared node row", roles=len(payload.roles))
        await record_event(
            session,
            event_id=str(uuid4()),
            category="nodes",
            name="node.create",
            level="INFO",
            fields={"node_id": payload.id, "name": payload.name},
        )
        op.step("event.record", "Recorded node create event")
        await session.commit()
        await session.refresh(node)
        op.step("db.commit", "Committed node create transaction")
        _logger.info("nodes.create", "Created node", node_id=node.id, name=node.name)
        return node


async def update_node(
    session: AsyncSession,
    node: Node,
    payload: NodeUpdate,
) -> Node:
    async with _logger.operation(
        "node.update",
        "Updating node",
        node_id=node.id,
    ) as op:
        changed = False
        if payload.name is not None:
            node.name = payload.name
            changed = True
            op.step("name.update", "Updated node name", name=node.name)
        if payload.roles is not None:
            node.roles = payload.roles
            changed = True
            op.step("roles.update", "Updated node roles", roles=len(node.roles))
        if payload.labels is not None:
            node.labels = payload.labels
            changed = True
            op.step("labels.update", "Updated node labels", labels=len(node.labels))
        if payload.mesh_ip is not None:
            node.mesh_ip = payload.mesh_ip
            changed = True
            op.step("mesh_ip.update", "Updated mesh IP", mesh_ip=node.mesh_ip or "")
        if payload.status is not None:
            node.status = payload.status
            changed = True
            op.step("status.update", "Updated node status", status_fields=len(node.status or {}))
        if payload.api_endpoint is not None:
            node.api_endpoint = payload.api_endpoint
            changed = True
            op.step("api_endpoint.update", "Updated API endpoint", api_endpoint=node.api_endpoint or "")

        if changed:
            await record_event(
                session,
                event_id=str(uuid4()),
                category="nodes",
                name="node.update",
                level="INFO",
                fields={"node_id": node.id},
            )
            op.step("event.record", "Recorded node update event")
        else:
            op.step("change.none", "No node fields changed")

        await session.commit()
        await session.refresh(node)
        op.step("db.commit", "Committed node update transaction")
        return node


async def cordon_node(session: AsyncSession, node: Node) -> Node:
    status = dict(node.status or {})
    status["schedulable"] = False
    status["cordoned_at"] = datetime.now(timezone.utc).isoformat()
    node.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="nodes",
        name="node.cordon",
        level="INFO",
        fields={"node_id": node.id},
    )
    await session.commit()
    await session.refresh(node)
    return node


async def uncordon_node(session: AsyncSession, node: Node) -> Node:
    status = dict(node.status or {})
    status["schedulable"] = True
    status["uncordoned_at"] = datetime.now(timezone.utc).isoformat()
    node.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="nodes",
        name="node.uncordon",
        level="INFO",
        fields={"node_id": node.id},
    )
    await session.commit()
    await session.refresh(node)
    return node


async def drain_node(session: AsyncSession, node: Node) -> Node:
    status = dict(node.status or {})
    status["draining"] = True
    status["drain_requested_at"] = datetime.now(timezone.utc).isoformat()
    status["schedulable"] = False
    node.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="nodes",
        name="node.drain",
        level="INFO",
        fields={"node_id": node.id},
    )
    await session.commit()
    await session.refresh(node)
    return node


async def mark_reboot(session: AsyncSession, node: Node) -> Node:
    status = dict(node.status or {})
    status["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
    node.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="nodes",
        name="node.reboot_marker",
        level="INFO",
        fields={"node_id": node.id},
    )
    await session.commit()
    await session.refresh(node)
    return node


async def rotate_wg_keys(session: AsyncSession, node: Node) -> Node:
    status = dict(node.status or {})
    status["wg_key_rotation_requested_at"] = datetime.now(timezone.utc).isoformat()
    node.status = status
    await record_event(
        session,
        event_id=str(uuid4()),
        category="wireguard",
        name="node.rotate_keys",
        level="INFO",
        fields={"node_id": node.id},
    )
    await session.commit()
    await session.refresh(node)
    return node
