from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ProviderCapabilityOut(BaseModel):
    provider: str
    configured: bool
    capabilities: List[str] = Field(default_factory=list)
    missing_settings: List[str] = Field(default_factory=list)


class ProviderAccountCreate(BaseModel):
    id: str
    provider: str
    display_name: str
    enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)


class ProviderAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    provider: str
    display_name: str
    enabled: bool
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProviderResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    provider: str
    resource_kind: str
    external_id: Optional[str]
    desired: Dict[str, Any]
    observed: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProviderActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    resource_id: Optional[str]
    action: str
    status: str
    plan: Dict[str, Any]
    result: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ProviderSummaryOut(BaseModel):
    capabilities: List[ProviderCapabilityOut]
    accounts: List[ProviderAccountOut]
    resources: List[ProviderResourceOut]
    actions: List[ProviderActionOut]
