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


class EtcdQuorumOut(BaseModel):
    enabled: bool
    configured: bool
    desired_member_ids: list[str]
    current_member_ids: list[str]
    missing_member_ids: list[str]
    extra_member_ids: list[str]
    endpoint_count: int
    healthy_endpoint_count: int
    quorum_required: int
    has_quorum: bool
    detail: str = ""


class EtcdQuorumReconcileCandidateOut(BaseModel):
    node_id: str
    peer_url: str = ""
    action: str
    reason: str = ""
    member_id: str = ""
    error: str = ""


class EtcdQuorumReconcileOut(BaseModel):
    dry_run: bool
    desired_member_count: int
    current_member_count: int
    added_count: int
    skipped_count: int
    failed_count: int
    candidates: list[EtcdQuorumReconcileCandidateOut]
