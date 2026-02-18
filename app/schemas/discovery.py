from __future__ import annotations

from pydantic import BaseModel


class DiscoveryEndpointOut(BaseModel):
    endpoint_id: str
    replica_id: str
    address: str
    port: int
    host: str
    host_fqdn: str


class DiscoveryServiceOut(BaseModel):
    service_id: str
    service_name: str
    service: str
    service_fqdn: str
    endpoints: list[DiscoveryEndpointOut]


class DiscoveryStatusOut(BaseModel):
    domain: str
    ttl_seconds: int
    zone_path: str
    corefile_path: str
    zone_exists: bool
    corefile_exists: bool
    zone_sha256: str
    corefile_sha256: str
    service_count: int
    endpoint_count: int
    last_sync_at: str
