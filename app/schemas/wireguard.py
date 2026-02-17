from __future__ import annotations

from pydantic import BaseModel


class WireGuardStatusOut(BaseModel):
    node_id: str
    primary_tunnel: str | None = None
    secondary_tunnel: str | None = None
    active_route: str | None = None
    failover_state: str | None = None
