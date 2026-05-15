from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class SurvivorFailureOut(BaseModel):
    failure_domain: str
    lost_node_id: str
    healthy_replicas_after_loss: int
    serving_capacity_after_loss: float
    current_demand: float
    serving: bool
    capacity_ok: bool


class SurvivorServiceOut(BaseModel):
    service_id: str
    service_name: str
    protection: str
    state: str
    desired_replicas: int
    total_replicas: int
    healthy_replicas: int
    healthy_nodes: int
    current_demand: float
    serving_capacity: float
    min_survivors: int
    failures: List[SurvivorFailureOut] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class SurvivorReportOut(BaseModel):
    services: List[SurvivorServiceOut] = Field(default_factory=list)
    protected: int
    degraded: int
    at_risk: int
    incidents: int


class ServiceStateDesiredOut(BaseModel):
    runtime: str
    desired_replicas: int
    gateway_enabled: bool
    protection: str


class ServiceStateObservedOut(BaseModel):
    total_replicas: int
    healthy_replicas: int
    healthy_endpoints: int
    healthy_nodes: int
    generation: int


class ServiceStateActionOut(BaseModel):
    action: str
    detail: str
    replica_id: Optional[str] = None
    node_id: Optional[str] = None


class ServiceStateOut(BaseModel):
    service_id: str
    service_name: str
    desired: ServiceStateDesiredOut
    observed: ServiceStateObservedOut
    survivor: SurvivorServiceOut
    actions: List[ServiceStateActionOut] = Field(default_factory=list)
