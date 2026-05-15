from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.validation import dns_name, mesh_id, nginx_path, port


class ServiceRuntimeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["static", "docker", "lxd"] = "static"


class ServiceHealthcheckSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = "/"
    expected_status: int = Field(default=200, ge=100, le=599)
    command: Optional[str] = None

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        return nginx_path(value, field_name="health path")


class ServiceContainerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    image: Optional[str] = None
    port: Optional[int] = None
    env: Dict[str, str] = Field(default_factory=dict)
    healthcheck: ServiceHealthcheckSpec = Field(default_factory=ServiceHealthcheckSpec)
    health_path: Optional[str] = None

    @field_validator("port")
    @classmethod
    def _validate_port(cls, value: Optional[int]) -> Optional[int]:
        return port(value, field_name="container.port") if value is not None else None

    @field_validator("health_path")
    @classmethod
    def _validate_health_path(cls, value: Optional[str]) -> Optional[str]:
        return nginx_path(value, field_name="container.health_path") if value else value


class ServiceGatewaySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    host: str = "_"
    path: str = "/"

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        return dns_name(value or "_", field_name="gateway.host", allow_wildcard=True)

    @field_validator("path")
    @classmethod
    def _validate_gateway_path(cls, value: str) -> str:
        return nginx_path(value or "/", field_name="gateway.path")


class ServiceAvailabilitySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protection: Literal["best_effort", "survive_one_failure", "protected"] = "best_effort"


class ServiceSchedulingSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    desired_replicas: int = Field(default=1, ge=0, le=1000)
    node_selector: Dict[str, str] = Field(default_factory=dict)
    anti_affinity: bool = True
    reschedule_unhealthy: bool = True


class ServiceRollingUpdateSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_surge: int = Field(default=1, ge=0, le=1000)
    max_unavailable: int = Field(default=0, ge=0, le=1000)


class ServicePinnedReplicaSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    replica_id: str
    node_id: str
    desired_state: str = "running"
    status: Dict[str, Any] = Field(default_factory=dict)


class ServicePlacementSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pinned_replicas: list[ServicePinnedReplicaSpec] = Field(default_factory=list)
    strict: bool = False


class ServiceCapacitySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_demand: float = Field(default=1.0, ge=0)
    per_replica: float = Field(default=1.0, gt=0)


class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    type_: Optional[Literal["static", "static_site", "container", "docker", "web_app", "lxd"]] = Field(
        default=None,
        alias="type",
    )
    runtime: ServiceRuntimeSpec = Field(default_factory=ServiceRuntimeSpec)
    container: Optional[ServiceContainerSpec] = None
    image: Optional[str] = None
    port: Optional[int] = None
    env: Optional[Dict[str, str]] = None
    gateway: ServiceGatewaySpec = Field(default_factory=ServiceGatewaySpec)
    availability: ServiceAvailabilitySpec = Field(default_factory=ServiceAvailabilitySpec)
    scheduling: ServiceSchedulingSpec = Field(default_factory=ServiceSchedulingSpec)
    rolling_update: ServiceRollingUpdateSpec = Field(default_factory=ServiceRollingUpdateSpec)
    placement: ServicePlacementSpec = Field(default_factory=ServicePlacementSpec)
    capacity: ServiceCapacitySpec = Field(default_factory=ServiceCapacitySpec)
    pinned_replicas: list[ServicePinnedReplicaSpec] = Field(default_factory=list)
    pinned_strict: bool = False
    rollout_requested_at: Optional[str] = None
    rollout_replica_count: Optional[int] = Field(default=None, ge=0)
    docker: Optional[ServiceContainerSpec] = None
    lxd: Optional[Dict[str, Any]] = None

    @field_validator("port")
    @classmethod
    def _validate_top_level_port(cls, value: Optional[int]) -> Optional[int]:
        return port(value, field_name="port") if value is not None else None

    @model_validator(mode="after")
    def _validate_runtime_contract(self) -> "ServiceSpec":
        kind = self.runtime.kind
        if self.type_ in {"container", "docker", "web_app"}:
            kind = "docker"
        elif self.type_ in {"static", "static_site"}:
            kind = "static"
        elif self.type_ == "lxd":
            kind = "lxd"
        if self.container is not None or self.docker is not None:
            kind = "docker"
        if self.lxd is not None:
            kind = "lxd"
        self.runtime.kind = kind

        container = self.container or self.docker
        if kind == "docker":
            image = (container.image if container else None) or self.image
            container_port = (container.port if container else None) or self.port
            if not image:
                raise ValueError("Docker web apps require container.image.")
            if container_port is None:
                raise ValueError("Docker web apps require container.port.")
        return self


def service_spec_to_dict(value: ServiceSpec | Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(value, ServiceSpec):
        return value.model_dump(by_alias=True, exclude_none=True)
    return dict(value)


class ServiceCreate(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    spec: ServiceSpec = Field(default_factory=ServiceSpec)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return mesh_id(value, field_name="service id")


class ServiceUpdate(BaseModel):
    description: Optional[str] = None
    spec: Optional[ServiceSpec] = None


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
