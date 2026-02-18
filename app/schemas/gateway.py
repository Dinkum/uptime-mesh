from __future__ import annotations

from pydantic import BaseModel


class GatewayRouteEndpointOut(BaseModel):
    address: str
    port: int


class GatewayRouteOut(BaseModel):
    service_id: str
    service_name: str
    host: str
    path: str
    upstream: str
    endpoint_count: int
    endpoints: list[GatewayRouteEndpointOut]


class GatewayStatusOut(BaseModel):
    enabled: bool
    config_path: str
    candidate_path: str
    backup_path: str
    listen: str
    server_name: str
    routes: int
    upstreams: int
    last_sync_at: str
    last_apply_status: str
    last_apply_error: str
    healthcheck_urls: list[str]
