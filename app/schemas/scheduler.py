from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class SchedulerActionOut(BaseModel):
    action: str
    service_id: str
    replica_id: Optional[str] = None
    source_node_id: Optional[str] = None
    target_node_id: Optional[str] = None
    detail: Optional[str] = None


class SchedulerResultOut(BaseModel):
    service_id: str
    desired_replicas: int
    actual_replicas: int
    eligible_nodes: int
    dry_run: bool
    warnings: List[str] = Field(default_factory=list)
    actions: List[SchedulerActionOut] = Field(default_factory=list)
    generated_at: datetime


class SchedulerBulkResultOut(BaseModel):
    dry_run: bool
    generated_at: datetime
    results: List[SchedulerResultOut] = Field(default_factory=list)
