from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ServiceCreate(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    spec: Dict[str, Any] = Field(default_factory=dict)


class ServiceUpdate(BaseModel):
    description: Optional[str] = None
    spec: Optional[Dict[str, Any]] = None


class ServiceRollback(BaseModel):
    target_generation: Optional[int] = None


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    spec: Dict[str, Any]
    generation: int
    created_at: datetime
    updated_at: datetime
