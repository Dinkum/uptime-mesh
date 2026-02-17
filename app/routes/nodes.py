from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.nodes import NodeCreate, NodeOut, NodeUpdate
from app.services import nodes as node_service

router = APIRouter(prefix="/nodes", tags=["nodes"])


@router.get("", response_model=List[NodeOut])
async def list_nodes(
    session: AsyncSession = Depends(get_db_session),
) -> List[NodeOut]:
    nodes = await node_service.list_nodes(session)
    return [NodeOut.model_validate(node) for node in nodes]


@router.get("/{node_id}", response_model=NodeOut)
async def get_node(
    node_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return NodeOut.model_validate(node)


@router.post("", response_model=NodeOut, status_code=status.HTTP_201_CREATED)
async def create_node(
    payload: NodeCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    if await node_service.get_node(session, payload.id):
        raise HTTPException(status_code=409, detail="Node id already exists")
    if await node_service.get_node_by_name(session, payload.name):
        raise HTTPException(status_code=409, detail="Node name already exists")
    node = await node_service.create_node(session, payload)
    return NodeOut.model_validate(node)


@router.patch("/{node_id}", response_model=NodeOut)
async def update_node(
    node_id: str,
    payload: NodeUpdate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.update_node(session, node, payload)
    return NodeOut.model_validate(updated)


@router.post("/{node_id}/cordon", response_model=NodeOut)
async def cordon_node(
    node_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.cordon_node(session, node)
    return NodeOut.model_validate(updated)


@router.post("/{node_id}/uncordon", response_model=NodeOut)
async def uncordon_node(
    node_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.uncordon_node(session, node)
    return NodeOut.model_validate(updated)


@router.post("/{node_id}/drain", response_model=NodeOut)
async def drain_node(
    node_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.drain_node(session, node)
    return NodeOut.model_validate(updated)


@router.post("/{node_id}/reboot-marker", response_model=NodeOut)
async def mark_reboot(
    node_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.mark_reboot(session, node)
    return NodeOut.model_validate(updated)


@router.post("/{node_id}/rotate-wg-keys", response_model=NodeOut)
async def rotate_wg_keys(
    node_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> NodeOut:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    updated = await node_service.rotate_wg_keys(session, node)
    return NodeOut.model_validate(updated)
