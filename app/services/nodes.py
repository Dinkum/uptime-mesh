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
    _logger.debug("nodes.list", "Listing nodes", limit=limit)
    result = await session.execute(select(Node).limit(limit))
    return list(result.scalars().all())


async def get_node(session: AsyncSession, node_id: str) -> Optional[Node]:
    result = await session.execute(select(Node).where(Node.id == node_id))
    return result.scalar_one_or_none()


async def get_node_by_name(session: AsyncSession, name: str) -> Optional[Node]:
    result = await session.execute(select(Node).where(Node.name == name))
    return result.scalar_one_or_none()


async def create_node(session: AsyncSession, payload: NodeCreate) -> Node:
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
    await record_event(
        session,
        event_id=str(uuid4()),
        category="nodes",
        name="node.create",
        level="INFO",
        fields={"node_id": payload.id, "name": payload.name},
    )
    await session.commit()
    await session.refresh(node)
    _logger.info("nodes.create", "Created node", node_id=node.id, name=node.name)
    return node


async def update_node(
    session: AsyncSession,
    node: Node,
    payload: NodeUpdate,
) -> Node:
    changed = False
    if payload.name is not None:
        node.name = payload.name
        changed = True
    if payload.roles is not None:
        node.roles = payload.roles
        changed = True
    if payload.labels is not None:
        node.labels = payload.labels
        changed = True
    if payload.mesh_ip is not None:
        node.mesh_ip = payload.mesh_ip
        changed = True
    if payload.status is not None:
        node.status = payload.status
        changed = True
    if payload.api_endpoint is not None:
        node.api_endpoint = payload.api_endpoint
        changed = True

    if changed:
        await record_event(
            session,
            event_id=str(uuid4()),
            category="nodes",
            name="node.update",
            level="INFO",
            fields={"node_id": node.id},
        )

    await session.commit()
    await session.refresh(node)
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
