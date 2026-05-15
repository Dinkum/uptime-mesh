from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.validation import artifact_id, mesh_id


class ReplicaCreate(BaseModel):
    id: str
    service_id: str
    node_id: str
    desired_state: str = "running"
    status: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", "service_id", "node_id")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        return mesh_id(value)


class ReplicaUpdate(BaseModel):
    desired_state: Optional[str] = None
    status: Optional[Dict[str, Any]] = None


class ReplicaMove(BaseModel):
    target_node_id: str

    @field_validator("target_node_id")
    @classmethod
    def _validate_target_node_id(cls, value: str) -> str:
        return mesh_id(value, field_name="target node id")


class ReplicaRestore(BaseModel):
    snapshot_id: Optional[str] = None

    @field_validator("snapshot_id")
    @classmethod
    def _validate_snapshot_id(cls, value: Optional[str]) -> Optional[str]:
        return artifact_id(value, field_name="snapshot id") if value else value


class ReplicaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    service_id: str
    node_id: str
    desired_state: str
    status: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
