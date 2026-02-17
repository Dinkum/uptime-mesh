from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ClusterSettingUpsert(BaseModel):
    value: str


class ClusterSettingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: str
    created_at: datetime
    updated_at: datetime
