from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ClusterBootstrapRequest(BaseModel):
    worker_token_ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class JoinTokenCreate(BaseModel):
    role: str = Field(default="general")
    ttl_seconds: int = Field(default=1800, ge=60, le=86400)


class JoinTokenOut(BaseModel):
    id: str
    role: str
    token: str
    expires_at: datetime


class ClusterBootstrapOut(BaseModel):
    bootstrapped: bool
    worker_token: JoinTokenOut


class NodeJoinRequest(BaseModel):
    token: str
    node_id: str
    name: str
    role: str = Field(default="general")
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
    auth_secret_key: str
    cluster_signing_key: str


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


class ClusterPeerOut(BaseModel):
    node_id: str
    name: str
    mesh_ip: str
    api_endpoint: str


class SwimReportRequest(BaseModel):
    node_id: str
    lease_token: str
    incarnation: int = Field(default=0, ge=0)
    state: str = Field(default="healthy")
    flags: Dict[str, Any] = Field(default_factory=dict)
    peers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class SwimMemberOut(BaseModel):
    node_id: str
    state: str
    incarnation: int
    updated_at: str
    flags: Dict[str, Any] = Field(default_factory=dict)
    peers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class SwimReportOut(BaseModel):
    node_id: str
    accepted: bool
    updated_at: str


class ContentActiveOut(BaseModel):
    version: str
    hash_sha256: str
    size_bytes: int
    body_base64: str
