from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.validation import mesh_id


class RouterAssignmentCreate(BaseModel):
    id: str
    node_id: str
    primary_router_id: str
    secondary_router_id: str

    @field_validator("id", "node_id", "primary_router_id", "secondary_router_id")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        return mesh_id(value)


class RouterAssignmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    node_id: str
    primary_router_id: str
    secondary_router_id: str
    created_at: datetime
    updated_at: datetime
