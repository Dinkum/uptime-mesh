from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RouterAssignmentCreate(BaseModel):
    id: str
    node_id: str
    primary_router_id: str
    secondary_router_id: str


class RouterAssignmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    node_id: str
    primary_router_id: str
    secondary_router_id: str
    created_at: datetime
    updated_at: datetime
