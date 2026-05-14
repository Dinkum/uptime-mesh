from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class SnapshotRunCreate(BaseModel):
    id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    requested_by: Optional[str] = None


class SnapshotRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    location: Optional[str]
    requested_by: Optional[str]
    error: Optional[str]
    created_at: datetime
    updated_at: datetime
