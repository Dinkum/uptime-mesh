from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Iterable

from app.config import get_settings
from app.logger import get_logger
from app.metrics import record_lxd_operation

_logger = get_logger("lxd")
_NAME_SAFE_RE = re.compile(r"[^a-z0-9-]")


class LXDOperationError(RuntimeError):
    def __init__(self, action: str, detail: str) -> None:
        super().__init__(f"{action}: {detail}")
        self.action = action
        self.detail = detail


class LXDUnavailableError(LXDOperationError):
    pass


@dataclass(frozen=True)
class LXDContainerSpec:
    name: str
    project: str
    image: str
    profiles: list[str]
    config: dict[str, str]
    target_node: str
    desired_running: bool


def _sanitize_label(raw: str, fallback: str) -> str:
    value = raw.strip().lower().replace("_", "-").replace(" ", "-")
    value = _NAME_SAFE_RE.sub("-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    if not value:
        value = fallback
    return value[:63]


def container_name(service_name: str, replica_id: str) -> str:
    svc = _sanitize_label(service_name, fallback="svc")
    rid = _sanitize_label(replica_id, fallback="rep")
    return _sanitize_label(f"{svc}-{rid}", fallback=rid)


def build_container_spec(
    *,
    service_name: str,
    service_spec: dict[str, Any],
    replica_id: str,
    node_name: str,
    desired_state: str,
) -> LXDContainerSpec:
    settings = get_settings()
    lxd_spec = service_spec.get("lxd") if isinstance(service_spec, dict) else {}
    if not isinstance(lxd_spec, dict):
        lxd_spec = {}

    raw_profiles = lxd_spec.get("profiles")
    profiles: list[str] = []
    if isinstance(raw_profiles, list):
        for item in raw_profiles:
            if isinstance(item, str) and item.strip():
                profiles.append(item.strip())
    if not profiles:
        profiles = [settings.lxd_default_profile]

    config_map: dict[str, str] = {}
    raw_config = lxd_spec.get("config")
    if isinstance(raw_config, dict):
        for key, value in raw_config.items():
            if isinstance(key, str) and key.strip():
                config_map[key.strip()] = str(value)

    name_value = lxd_spec.get("container_name")
    if isinstance(name_value, str) and name_value.strip():
        name = _sanitize_label(name_value, fallback=replica_id)
    else:
        name = container_name(service_name, replica_id)

    project = str(lxd_spec.get("project", settings.lxd_project)).strip() or settings.lxd_project
    image = (
        str(lxd_spec.get("image", settings.lxd_default_image)).strip() or settings.lxd_default_image
    )
    target = str(lxd_spec.get("target_node", node_name)).strip()
    return LXDContainerSpec(
        name=name,
        project=project,
        image=image,
        profiles=profiles,
        config=config_map,
        target_node=target,
        desired_running=desired_state.lower() == "running",
    )


def _run_lxc(
    *,
    args: Iterable[str],
    project: str,
    timeout_seconds: int = 30,
) -> tuple[int, str, str]:
    settings = get_settings()
    cmd = [settings.lxd_command]
    if project:
        cmd.extend(["--project", project])
    cmd.extend(args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LXDUnavailableError("lxd.command", str(exc)) from exc
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


async def _run_lxc_checked(
    *,
    args: Iterable[str],
    project: str,
    action: str,
    timeout_seconds: int = 30,
) -> str:
    arg_list = list(args)
    code, out, err = await asyncio.to_thread(
        _run_lxc,
        args=tuple(arg_list),
        project=project,
        timeout_seconds=timeout_seconds,
    )
    if code != 0:
        record_lxd_operation(action=action, ok=False)
        _logger.warning(
            "lxd.command.fail",
            "LXD command failed",
            action=action,
            project=project,
            args=" ".join(arg_list),
            exit_code=code,
            stderr=err,
            stdout=out,
        )
        raise LXDOperationError(action, err or out or f"exit_{code}")
    record_lxd_operation(action=action, ok=True)
    _logger.debug(
        "lxd.command.ok",
        "LXD command succeeded",
        action=action,
        project=project,
        args=" ".join(arg_list),
    )
    return out


async def container_exists(*, name: str, project: str) -> bool:
    code, _, _ = await asyncio.to_thread(
        _run_lxc,
        args=("list", name, "--format=json"),
        project=project,
        timeout_seconds=20,
    )
    return code == 0


async def container_status(*, name: str, project: str) -> str:
    out = await _run_lxc_checked(
        args=("list", name, "--format=json"),
        project=project,
        action="container.status",
        timeout_seconds=20,
    )
    payload = json.loads(out)
    if not isinstance(payload, list) or not payload:
        return "unknown"
    row = payload[0]
    if not isinstance(row, dict):
        return "unknown"
    status = row.get("status")
    if not isinstance(status, str):
        return "unknown"
    return status.lower()


async def wait_for_running(*, name: str, project: str) -> None:
    settings = get_settings()
    deadline = time.time() + settings.lxd_health_timeout_seconds
    while time.time() < deadline:
        status = await container_status(name=name, project=project)
        if status == "running":
            return
        await asyncio.sleep(settings.lxd_health_poll_seconds)
    raise LXDOperationError(
        "container.health_gate",
        f"container did not reach running within {settings.lxd_health_timeout_seconds}s",
    )


async def ensure_container(spec: LXDContainerSpec) -> None:
    async with _logger.operation(
        "container.ensure",
        "Ensuring LXD container",
        container=spec.name,
        project=spec.project,
        image=spec.image,
        target_node=spec.target_node,
    ) as op:
        if not await container_exists(name=spec.name, project=spec.project):
            cmd = ["init", spec.image, spec.name]
            for profile in spec.profiles:
                cmd.extend(["-p", profile])
            if spec.target_node:
                cmd.extend(["--target", spec.target_node])
            await _run_lxc_checked(
                args=tuple(cmd),
                project=spec.project,
                action="container.init",
                timeout_seconds=90,
            )
            op.step("container.init", "Initialized container")
        else:
            op.step("container.exists", "Container already exists")

        for key, value in spec.config.items():
            await _run_lxc_checked(
                args=("config", "set", spec.name, key, value),
                project=spec.project,
                action="container.config",
                timeout_seconds=30,
            )
            op.child("container.config", key, "Applied container config key", value=value)
        if spec.config:
            op.step("container.config", "Applied container config", keys=len(spec.config))

        if spec.desired_running:
            await _run_lxc_checked(
                args=("start", spec.name),
                project=spec.project,
                action="container.start",
                timeout_seconds=60,
            )
            await wait_for_running(name=spec.name, project=spec.project)
            op.step("container.health_gate", "Container reached running state")


async def restart_container(*, name: str, project: str) -> None:
    await _run_lxc_checked(
        args=("restart", name),
        project=project,
        action="container.restart",
        timeout_seconds=60,
    )
    await wait_for_running(name=name, project=project)


async def start_container(*, name: str, project: str) -> None:
    await _run_lxc_checked(
        args=("start", name),
        project=project,
        action="container.start",
        timeout_seconds=60,
    )
    await wait_for_running(name=name, project=project)


async def stop_container(*, name: str, project: str) -> None:
    await _run_lxc_checked(
        args=("stop", name, "--force"),
        project=project,
        action="container.stop",
        timeout_seconds=60,
    )


async def snapshot_container(*, name: str, project: str, snapshot: str) -> None:
    await _run_lxc_checked(
        args=("snapshot", name, snapshot),
        project=project,
        action="container.snapshot",
        timeout_seconds=60,
    )


async def list_snapshots(*, name: str, project: str) -> list[str]:
    out = await _run_lxc_checked(
        args=("info", name, "--format=json"),
        project=project,
        action="container.info",
        timeout_seconds=30,
    )
    payload = json.loads(out)
    if not isinstance(payload, dict):
        return []
    raw = payload.get("snapshots")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name_value = item.get("name")
        if not isinstance(name_value, str) or not name_value.strip():
            continue
        part = name_value.strip()
        if "/" in part:
            part = part.split("/", 1)[1]
        names.append(part)
    return names


async def restore_container(*, name: str, project: str, snapshot: str) -> None:
    await _run_lxc_checked(
        args=("restore", name, snapshot),
        project=project,
        action="container.restore",
        timeout_seconds=120,
    )
    await wait_for_running(name=name, project=project)


async def delete_container(*, name: str, project: str) -> None:
    if not await container_exists(name=name, project=project):
        return
    await _run_lxc_checked(
        args=("delete", name, "--force"),
        project=project,
        action="container.delete",
        timeout_seconds=60,
    )


async def move_container(*, name: str, project: str, target_node: str) -> None:
    if not target_node:
        raise LXDOperationError("container.move", "target node is required")
    await _run_lxc_checked(
        args=("move", name, name, "--target", target_node),
        project=project,
        action="container.move",
        timeout_seconds=120,
    )
    await wait_for_running(name=name, project=project)
