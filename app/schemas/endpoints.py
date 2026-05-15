from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.validation import host_or_ip, mesh_id, port


class EndpointCreate(BaseModel):
    id: str
    replica_id: str
    address: str
    port: int
    healthy: bool = True

    @field_validator("id", "replica_id")
    @classmethod
    def _validate_ids(cls, value: str) -> str:
        return mesh_id(value)

    @field_validator("address")
    @classmethod
    def _validate_address(cls, value: str) -> str:
        return host_or_ip(value, field_name="endpoint address")

    @field_validator("port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        return port(value, field_name="endpoint port")


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
