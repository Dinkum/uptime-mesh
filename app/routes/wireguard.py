from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session
from app.schemas.wireguard import WireGuardStatusOut
from app.services import nodes as node_service

router = APIRouter(prefix="/wireguard", tags=["wireguard"])


@router.get("/status", response_model=List[WireGuardStatusOut])
async def wireguard_status(
    session: AsyncSession = Depends(get_db_session),
) -> List[WireGuardStatusOut]:
    nodes = await node_service.list_nodes(session, limit=500)
    statuses: List[WireGuardStatusOut] = []
    for node in nodes:
        status = node.status or {}
        statuses.append(
            WireGuardStatusOut(
                node_id=node.id,
                primary_tunnel=status.get("wg_primary_tunnel"),
                secondary_tunnel=status.get("wg_secondary_tunnel"),
                primary_router_reachable=status.get("wg_primary_router_reachable"),
                secondary_router_reachable=status.get("wg_secondary_router_reachable"),
                active_route=status.get("wg_active_route"),
                failover_state=status.get("wg_failover_state"),
                primary_peer_configured=status.get("wg_primary_peer_configured"),
                secondary_peer_configured=status.get("wg_secondary_peer_configured"),
                primary_peer_endpoint=status.get("wg_primary_peer_endpoint"),
                secondary_peer_endpoint=status.get("wg_secondary_peer_endpoint"),
            )
        )
    return statuses
