from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class NodeCreate(BaseModel):
    id: str
    name: str
    roles: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    mesh_ip: Optional[str] = None
    status: Dict[str, Any] = Field(default_factory=dict)
    api_endpoint: Optional[str] = None


class NodeUpdate(BaseModel):
    name: Optional[str] = None
    roles: Optional[List[str]] = None
    labels: Optional[Dict[str, str]] = None
    mesh_ip: Optional[str] = None
    status: Optional[Dict[str, Any]] = None
    api_endpoint: Optional[str] = None


class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    roles: List[str]
    labels: Dict[str, str]
    mesh_ip: Optional[str]
    status: Dict[str, Any]
    api_endpoint: Optional[str]
    heartbeat_at: Optional[datetime]
    lease_expires_at: Optional[datetime]
    identity_fingerprint: Optional[str]
    identity_expires_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
