from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class SupportBundleCreate(BaseModel):
    id: Optional[str] = None
    requested_by: Optional[str] = None


class SupportBundleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    path: Optional[str]
    requested_by: Optional[str]
    error: Optional[str]
    created_at: datetime
    updated_at: datetime
