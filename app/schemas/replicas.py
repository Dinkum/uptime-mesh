from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReplicaCreate(BaseModel):
    id: str
    service_id: str
    node_id: str
    desired_state: str = "running"
    status: Dict[str, Any] = Field(default_factory=dict)


class ReplicaUpdate(BaseModel):
    desired_state: Optional[str] = None
    status: Optional[Dict[str, Any]] = None


class ReplicaMove(BaseModel):
    target_node_id: str


class ReplicaRestore(BaseModel):
    snapshot_id: Optional[str] = None


class ReplicaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    service_id: str
    node_id: str
    desired_state: str
    status: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
