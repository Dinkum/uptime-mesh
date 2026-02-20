from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class RoleSpecUpsert(BaseModel):
    kind: str = Field(default="replicated")
    min_replicas: int = Field(default=1, ge=0)
    max_replicas: int = Field(default=0, ge=0)
    ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    priority: int = Field(default=50, ge=0, le=1000)
    strict_separation_with: List[str] = Field(default_factory=list)
    cooldown_seconds: int = Field(default=30, ge=0, le=3600)
    slot_count: int = Field(default=0, ge=0)
    runtime_template: str = Field(default="")


class RoleSpecOut(RoleSpecUpsert):
    name: str


class RolePlacementRoleOut(BaseModel):
    name: str
    desired: int
    assigned: int
    deficit: int
    holders: List[str] = Field(default_factory=list)
    priority: int
    ratio: float
    min_replicas: int
    max_replicas: int


class RolePlacementOut(BaseModel):
    generated_at: str
    healthy_nodes: List[str] = Field(default_factory=list)
    swim_states: Dict[str, str] = Field(default_factory=dict)
    roles: List[RolePlacementRoleOut] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    placement_map: Dict[str, List[str]] = Field(default_factory=dict)
    node_assignments: Dict[str, List[str]] = Field(default_factory=dict)
    source: str = Field(default="runtime")
    persisted: bool = False
    previous_generated_at: Optional[str] = None
