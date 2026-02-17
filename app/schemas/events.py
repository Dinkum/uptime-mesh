from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field


class EventCreate(BaseModel):
    id: str | None = None
    category: str
    name: str
    level: str
    fields: Dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    category: str
    name: str
    level: str
    fields: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
