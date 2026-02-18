from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ClusterBootstrapRequest(BaseModel):
    core_token_ttl_seconds: int = Field(default=1800, ge=60, le=86400)
    worker_token_ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class JoinTokenCreate(BaseModel):
    role: str = Field(pattern="^(core|worker|gateway)$")
    ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class JoinTokenOut(BaseModel):
    id: str
    role: str
    token: str
    expires_at: datetime


class ClusterBootstrapOut(BaseModel):
    bootstrapped: bool
    core_token: JoinTokenOut
    worker_token: JoinTokenOut


class NodeJoinRequest(BaseModel):
    token: str
    node_id: str
    name: str
    role: str = Field(pattern="^(core|worker|gateway)$")
    mesh_ip: Optional[str] = None
    api_endpoint: Optional[str] = None
    etcd_peer_url: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    status: Dict[str, Any] = Field(default_factory=dict)
    lease_ttl_seconds: int = Field(default=45, ge=10, le=300)
    csr_pem: str


class NodeJoinOut(BaseModel):
    node_id: str
    lease_token: str
    lease_expires_at: datetime
    identity_fingerprint: str
    node_cert_pem: str
    ca_cert_pem: str


class HeartbeatRequest(BaseModel):
    node_id: str
    lease_token: str
    ttl_seconds: int = Field(default=45, ge=10, le=300)
    status_patch: Dict[str, Any] = Field(default_factory=dict)
    signed_at: int
    signature: str


class HeartbeatOut(BaseModel):
    node_id: str
    heartbeat_at: datetime
    lease_expires_at: datetime
    lease_state: str


class NodeLeaseOut(BaseModel):
    node_id: str
    name: str
    roles: List[str]
    heartbeat_at: Optional[datetime]
    lease_expires_at: Optional[datetime]
    lease_state: str
