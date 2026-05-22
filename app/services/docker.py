from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

from app.config import get_settings
from app.logger import get_logger
from app.utils import sanitize_label

_logger = get_logger("docker")


class DockerOperationError(RuntimeError):
    def __init__(self, action: str, detail: str) -> None:
        super().__init__(f"{action}: {detail}")
        self.action = action
        self.detail = detail


class DockerUnavailableError(DockerOperationError):
    pass


@dataclass(frozen=True)
class DockerContainerSpec:
    name: str
    image: str
    port: int
    host_port: int
    env: dict[str, str]
    network: str
    docker_host: str
    labels: dict[str, str]
    health_path: str
    health_expected_status: int
    health_command: str
    desired_running: bool


def _sanitize_label(raw: str, fallback: str) -> str:
    value = sanitize_label(raw, max_len=63)
    if not value:
        value = sanitize_label(fallback, max_len=63)
    return value or "item"


def container_name(service_name: str, replica_id: str) -> str:
    svc = _sanitize_label(service_name, fallback="svc")
    rid = _sanitize_label(replica_id, fallback="rep")
    return _sanitize_label(f"um-{svc}-{rid}", fallback=rid)


def _node_endpoint_host(node: Any) -> str:
    mesh_ip = str(getattr(node, "mesh_ip", "") or "").strip()
    if mesh_ip:
        return mesh_ip
    endpoint = str(getattr(node, "api_endpoint", "") or "").strip()
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.hostname:
            return parsed.hostname
    return "127.0.0.1"


def endpoint_for_container(*, node: Any, spec: DockerContainerSpec) -> tuple[str, int]:
    return _node_endpoint_host(node), spec.host_port


def _required_int(value: Any, *, action: str, field: str) -> int:
    if value is None:
        raise DockerOperationError(action, f"{field} is required")
    return int(value)


def build_container_spec(
    *,
    service_name: str,
    service_spec: dict[str, Any],
    replica_id: str,
    node: Any,
    desired_state: str,
) -> DockerContainerSpec:
    settings = get_settings()
    container = service_spec.get("container") if isinstance(service_spec, dict) else {}
    container_map = container if isinstance(container, dict) else {}
    health = container_map.get("healthcheck")
    health_map = health if isinstance(health, dict) else {}
    status = getattr(node, "status", {}) or {}
    docker_host = str(container_map.get("docker_host") or status.get("docker_host") or "").strip()
    port = _required_int(container_map.get("port"), action="container.spec", field="container.port")
    host_port = int(container_map.get("host_port") or port)
    env_raw = container_map.get("env")
    env = env_raw if isinstance(env_raw, dict) else {}
    labels = {
        "uptimemesh.service": service_name,
        "uptimemesh.replica": replica_id,
        "uptimemesh.node": str(getattr(node, "id", "")),
    }
    return DockerContainerSpec(
        name=container_name(service_name, replica_id),
        image=str(container_map.get("image") or "").strip(),
        port=port,
        host_port=host_port,
        env={str(key): str(value) for key, value in env.items()},
        network=str(container_map.get("network") or settings.docker_default_network).strip() or "bridge",
        docker_host=docker_host,
        labels=labels,
        health_path=str(health_map.get("path") or "/"),
        health_expected_status=int(health_map.get("expected_status") or 200),
        health_command=str(health_map.get("command") or "").strip(),
        desired_running=desired_state.lower() == "running",
    )


def _timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_docker(
    *,
    args: Iterable[str],
    docker_host: str = "",
    timeout_seconds: int = 30,
) -> tuple[int, str, str]:
    settings = get_settings()
    cmd = [settings.docker_command, *list(args)]
    env = os.environ.copy()
    if docker_host:
        env["DOCKER_HOST"] = docker_host
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise DockerUnavailableError("docker.command", str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        stdout = _timeout_output(exc.stdout)
        stderr = _timeout_output(exc.stderr) or f"timed out after {timeout_seconds}s"
        raise DockerOperationError("docker.timeout", stderr.strip() or stdout.strip()) from exc
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


async def _run_docker_checked(
    *,
    args: Iterable[str],
    docker_host: str = "",
    action: str,
    timeout_seconds: int = 30,
) -> str:
    arg_list = list(args)
    try:
        code, out, err = await asyncio.to_thread(
            _run_docker,
            args=tuple(arg_list),
            docker_host=docker_host,
            timeout_seconds=timeout_seconds,
        )
    except DockerOperationError:
        raise
    if code != 0:
        _logger.warning(
            "docker.command.fail",
            "Docker command failed",
            action=action,
            args=" ".join(arg_list),
            exit_code=code,
            stderr=err,
            stdout=out,
        )
        raise DockerOperationError(action, err or out or f"exit_{code}")
    return out


async def container_exists(*, name: str, docker_host: str = "") -> bool:
    code, out, _ = await asyncio.to_thread(
        _run_docker,
        args=("ps", "-a", "--filter", f"name=^{name}$", "--format", "{{json .}}"),
        docker_host=docker_host,
        timeout_seconds=20,
    )
    return code == 0 and bool(out.strip())


async def container_status(*, name: str, docker_host: str = "") -> str:
    out = await _run_docker_checked(
        args=("inspect", name, "--format", "{{json .State}}"),
        docker_host=docker_host,
        action="container.status",
        timeout_seconds=20,
    )
    try:
        state = json.loads(out)
    except json.JSONDecodeError:
        return "unknown"
    if not isinstance(state, dict):
        return "unknown"
    status = str(state.get("Status") or "unknown").lower()
    health = state.get("Health")
    if isinstance(health, dict):
        health_status = str(health.get("Status") or "").lower()
        if health_status:
            return f"{status}:{health_status}"
    return status


async def wait_for_running(*, name: str, docker_host: str = "") -> None:
    settings = get_settings()
    deadline = time.time() + settings.docker_health_timeout_seconds
    while time.time() < deadline:
        status = await container_status(name=name, docker_host=docker_host)
        if status in {"running", "running:healthy"}:
            return
        await asyncio.sleep(settings.docker_health_poll_seconds)
    raise DockerOperationError(
        "container.health_gate",
        f"container did not reach healthy running state within {settings.docker_health_timeout_seconds}s",
    )


async def ensure_container(spec: DockerContainerSpec) -> None:
    async with _logger.operation(
        "container.ensure",
        "Ensuring Docker container",
        container=spec.name,
        image=spec.image,
        docker_host=spec.docker_host,
    ) as op:
        await _run_docker_checked(
            args=("pull", spec.image),
            docker_host=spec.docker_host,
            action="container.pull",
            timeout_seconds=180,
        )
        if await container_exists(name=spec.name, docker_host=spec.docker_host):
            await delete_container(name=spec.name, docker_host=spec.docker_host)
            op.step("container.replace", "Removed existing container before recreate")

        cmd = [
            "run",
            "-d",
            "--name",
            spec.name,
            "--restart",
            "unless-stopped",
            "--network",
            spec.network,
            "-p",
            f"{spec.host_port}:{spec.port}",
        ]
        for key, value in sorted(spec.env.items()):
            cmd.extend(["-e", f"{key}={value}"])
        for key, value in sorted(spec.labels.items()):
            cmd.extend(["--label", f"{key}={value}"])
        health_url = f"http://127.0.0.1:{spec.port}{spec.health_path}"
        health_command = spec.health_command or (
            f"status=$(curl -o /dev/null -s -w '%{{http_code}}' {health_url} || true); "
            f"test \"$status\" = \"{spec.health_expected_status}\" "
            "|| python3 -c \"import sys,urllib.request; "
            f"r=urllib.request.urlopen('{health_url}', timeout=3); "
            f"sys.exit(0 if r.status == {spec.health_expected_status} else 1)\" "
            f"|| wget -q -O /dev/null {health_url}"
        )
        cmd.extend(
            [
                "--health-cmd",
                health_command,
                "--health-interval",
                "10s",
                "--health-timeout",
                "3s",
                "--health-retries",
                "3",
                spec.image,
            ]
        )
        await _run_docker_checked(
            args=tuple(cmd),
            docker_host=spec.docker_host,
            action="container.run",
            timeout_seconds=90,
        )
        op.step("container.run", "Started Docker container")
        if spec.desired_running:
            await wait_for_running(name=spec.name, docker_host=spec.docker_host)
            op.step("container.health_gate", "Container reached running state")


async def restart_container(*, name: str, docker_host: str = "") -> None:
    await _run_docker_checked(
        args=("restart", name),
        docker_host=docker_host,
        action="container.restart",
        timeout_seconds=60,
    )
    await wait_for_running(name=name, docker_host=docker_host)


async def start_container(*, name: str, docker_host: str = "") -> None:
    await _run_docker_checked(
        args=("start", name),
        docker_host=docker_host,
        action="container.start",
        timeout_seconds=60,
    )
    await wait_for_running(name=name, docker_host=docker_host)


async def stop_container(*, name: str, docker_host: str = "") -> None:
    await _run_docker_checked(
        args=("stop", name),
        docker_host=docker_host,
        action="container.stop",
        timeout_seconds=60,
    )


async def delete_container(*, name: str, docker_host: str = "") -> None:
    if not await container_exists(name=name, docker_host=docker_host):
        return
    await _run_docker_checked(
        args=("rm", "-f", name),
        docker_host=docker_host,
        action="container.delete",
        timeout_seconds=60,
    )
