from __future__ import annotations

from pydantic import BaseModel


class EtcdEndpointHealthOut(BaseModel):
    endpoint: str
    healthy: bool
    error: str = ""
    took_seconds: float = 0.0


class EtcdStatusOut(BaseModel):
    enabled: bool
    configured: bool
    endpoints: list[str]
    healthy: bool
    details: list[EtcdEndpointHealthOut]


class EtcdMemberOut(BaseModel):
    member_id: str
    name: str
    peer_urls: list[str]
    client_urls: list[str]
    is_learner: bool


class EtcdMemberAddRequest(BaseModel):
    name: str
    peer_urls: list[str]
    is_learner: bool = False
