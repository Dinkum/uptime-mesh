from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class EndpointCreate(BaseModel):
    id: str
    replica_id: str
    address: str
    port: int
    healthy: bool = True


class EndpointUpdate(BaseModel):
    healthy: Optional[bool] = None


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    replica_id: str
    address: str
    port: int
    healthy: bool
    last_checked_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
