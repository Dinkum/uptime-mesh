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

