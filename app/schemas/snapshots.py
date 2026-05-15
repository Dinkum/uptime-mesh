from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.validation import artifact_id


class SnapshotRunCreate(BaseModel):
    id: Optional[str] = None
    requested_by: Optional[str] = None

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: Optional[str]) -> Optional[str]:
        return artifact_id(value, field_name="snapshot id") if value else value


class SnapshotRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    location: Optional[str]
    requested_by: Optional[str]
    error: Optional[str]
    created_at: datetime
    updated_at: datetime
