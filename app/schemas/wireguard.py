from __future__ import annotations

from pydantic import BaseModel


class WireGuardStatusOut(BaseModel):
    node_id: str
    primary_tunnel: str | None = None
    secondary_tunnel: str | None = None
    primary_router_reachable: bool | None = None
    secondary_router_reachable: bool | None = None
    active_route: str | None = None
    failover_state: str | None = None
    primary_peer_configured: bool | None = None
    secondary_peer_configured: bool | None = None
    primary_peer_endpoint: str | None = None
    secondary_peer_endpoint: str | None = None
