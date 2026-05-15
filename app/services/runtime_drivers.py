from __future__ import annotations

from typing import Any

from app.validation import nginx_path, port


SUPPORTED_RUNTIME_KINDS = {"static", "docker", "lxd"}


def runtime_kind_for_spec(spec: dict[str, Any]) -> str:
    runtime = spec.get("runtime")
    runtime_map = runtime if isinstance(runtime, dict) else {}
    explicit = str(runtime_map.get("kind") or spec.get("runtime") or spec.get("type") or "").strip().lower()
    if explicit in {"container", "docker", "web_app", "web-app"}:
        return "docker"
    if explicit in {"static", "static_site", "static-site"}:
        return "static"
    if explicit == "lxd":
        return "lxd"
    if isinstance(spec.get("container"), dict):
        return "docker"
    if isinstance(spec.get("docker"), dict):
        return "docker"
    if isinstance(spec.get("lxd"), dict):
        return "lxd"
    return "static"


def desired_replicas_for_spec(spec: dict[str, Any], default: int = 0) -> int:
    scheduling = spec.get("scheduling")
    scheduling_map = scheduling if isinstance(scheduling, dict) else {}
    value = scheduling_map.get("desired_replicas", spec.get("replicas_desired", default))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(parsed, 0)


def normalize_service_spec(spec: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(spec or {})
    kind = runtime_kind_for_spec(normalized)
    runtime = normalized.get("runtime")
    runtime_map = dict(runtime) if isinstance(runtime, dict) else {}
    runtime_map["kind"] = kind
    normalized["runtime"] = runtime_map

    if kind != "docker":
        return normalized

    container = normalized.get("container")
    container_map = dict(container) if isinstance(container, dict) else {}
    docker = normalized.get("docker")
    if isinstance(docker, dict):
        container_map = {**docker, **container_map}

    image = str(container_map.get("image") or normalized.get("image") or "").strip()
    if not image:
        raise ValueError("Docker web apps require container.image.")
    container_map["image"] = image

    port_int = port(container_map.get("port", normalized.get("port")), field_name="container.port")
    container_map["port"] = port_int

    healthcheck = container_map.get("healthcheck")
    health_map = dict(healthcheck) if isinstance(healthcheck, dict) else {}
    path = str(health_map.get("path") or container_map.get("health_path") or "/").strip()
    health_map["path"] = nginx_path(path or "/", field_name="container.healthcheck.path")
    try:
        expected_status = int(health_map.get("expected_status", 200))
    except (TypeError, ValueError):
        expected_status = 200
    health_map["expected_status"] = min(max(expected_status, 100), 599)
    command = str(health_map.get("command") or "").strip()
    if command:
        health_map["command"] = command
    container_map["healthcheck"] = health_map

    env = container_map.get("env")
    if env is None:
        env = normalized.get("env")
    if env is None:
        env = {}
    if not isinstance(env, dict):
        raise ValueError("Docker web app env must be an object when provided.")
    container_map["env"] = {str(key): str(value) for key, value in env.items() if str(key).strip()}

    normalized["container"] = container_map
    normalized.pop("docker", None)

    scheduling = normalized.get("scheduling")
    scheduling_map = dict(scheduling) if isinstance(scheduling, dict) else {}
    if "desired_replicas" not in scheduling_map:
        availability = normalized.get("availability")
        availability_map = availability if isinstance(availability, dict) else {}
        protected = str(availability_map.get("protection") or "").strip().lower()
        scheduling_map["desired_replicas"] = 2 if protected in {"survive_one_failure", "protected"} else 1
    normalized["scheduling"] = scheduling_map
    return normalized
