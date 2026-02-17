from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib import error, request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from app.config import Settings
from app.dependencies import get_sessionmaker
from app.identity import heartbeat_signing_message
from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting
from app.models.node import Node
from app.security import SESSION_COOKIE_NAME

_logger = get_logger("runtime")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_bool_health(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    value = payload.get("health")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "ok", "healthy"}
    return False


def _run_command(cmd: Sequence[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return process.returncode, process.stdout.strip(), process.stderr.strip()


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = 5,
    session_token: str = "",
) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    body: Optional[bytes] = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if session_token:
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={session_token}"

    req = request.Request(url=url, method=method, data=body, headers=headers)
    with request.urlopen(req, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8")
    if not raw:
        return {}
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        return parsed
    return {}


def _sign_heartbeat(private_key_pem: bytes, message: bytes) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(message, PKCS1v15(), hashes.SHA256())
    else:
        raise RuntimeError("Unsupported private key type for heartbeat signing.")
    return base64.b64encode(signature).decode("ascii")


@dataclass
class _FailoverState:
    active_iface: str
    primary_failures: int = 0
    primary_successes: int = 0
    secondary_failures: int = 0
    secondary_successes: int = 0


class RuntimeController:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []
        self._sessionmaker = get_sessionmaker(settings.database_url)
        self._failover = _FailoverState(active_iface=settings.runtime_wg_primary_iface)
        self._missing_identity_logged_at = 0.0
        self._missing_tools_logged_at = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self._settings.runtime_enable or self._settings.runtime_etcd_endpoints.strip())

    async def start(self) -> None:
        if not self.enabled:
            _logger.info("runtime.disabled", "Runtime controller is disabled")
            return

        endpoints = self._etcd_endpoints()
        if endpoints:
            self._tasks.append(asyncio.create_task(self._etcd_probe_loop(endpoints)))
            _logger.info(
                "runtime.etcd.start",
                "Started etcd probe loop",
                endpoints=",".join(endpoints),
                interval_seconds=self._settings.runtime_etcd_probe_interval_seconds,
            )

        if self._settings.runtime_enable:
            self._tasks.append(asyncio.create_task(self._node_agent_loop()))
            _logger.info(
                "runtime.agent.start",
                "Started node runtime loop",
                node_id=self._settings.runtime_node_id,
                api_base_url=self._settings.runtime_api_base_url,
                interval_seconds=self._settings.runtime_heartbeat_interval_seconds,
            )

    async def stop(self) -> None:
        self._stop.set()
        if not self._tasks:
            return
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        _logger.info("runtime.stop", "Stopped runtime controller")

    def _etcd_endpoints(self) -> list[str]:
        raw = self._settings.runtime_etcd_endpoints.strip()
        if not raw:
            return []
        endpoints = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
        return endpoints

    async def _etcd_probe_loop(self, endpoints: list[str]) -> None:
        interval = self._settings.runtime_etcd_probe_interval_seconds
        while not self._stop.is_set():
            status = "down"
            healthy_endpoint = ""
            error_detail = ""
            for endpoint in endpoints:
                ok, detail = await asyncio.to_thread(self._probe_etcd_endpoint, endpoint)
                if ok:
                    status = "ok"
                    healthy_endpoint = endpoint
                    break
                error_detail = detail

            updates: dict[str, str] = {"etcd_status": status}
            if status == "ok":
                updates["etcd_last_sync_at"] = _utcnow_iso()
            changed = await self._upsert_cluster_settings(updates)
            if changed:
                if status == "ok":
                    _logger.info(
                        "runtime.etcd.ok",
                        "Updated etcd status to ok",
                        endpoint=healthy_endpoint,
                    )
                else:
                    _logger.warning(
                        "runtime.etcd.down",
                        "Updated etcd status to down",
                        detail=error_detail,
                    )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    def _probe_etcd_endpoint(self, endpoint: str) -> tuple[bool, str]:
        health_url = f"{endpoint}/health"
        try:
            payload = _http_json(health_url, method="GET", timeout_seconds=3)
        except error.HTTPError as exc:
            return False, f"http_{exc.code}"
        except Exception as exc:  # noqa: BLE001
            return False, type(exc).__name__

        return (_parse_bool_health(payload), "unhealthy_payload")

    async def _node_agent_loop(self) -> None:
        interval = self._settings.runtime_heartbeat_interval_seconds
        while not self._stop.is_set():
            try:
                status_patch = await asyncio.to_thread(self._reconcile_wireguard_state)
                await self._send_heartbeat(status_patch)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                _logger.exception(
                    "runtime.agent.error",
                    "Node runtime loop failed",
                    error_type=type(exc).__name__,
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    def _identity_paths(self) -> dict[str, Path]:
        root = Path(self._settings.runtime_identity_dir) / self._settings.runtime_node_id
        return {
            "key": root / "node.key",
            "lease": root / "lease.token",
        }

    def _reconcile_wireguard_state(self) -> Dict[str, Any]:
        primary_iface = self._settings.runtime_wg_primary_iface
        secondary_iface = self._settings.runtime_wg_secondary_iface
        primary_router = self._settings.runtime_wg_primary_router_ip.strip()
        secondary_router = self._settings.runtime_wg_secondary_router_ip.strip()

        primary_up = self._interface_exists(primary_iface)
        secondary_up = self._interface_exists(secondary_iface)
        primary_reachable = primary_up and self._router_reachable(primary_router, primary_iface)
        secondary_reachable = secondary_up and self._router_reachable(secondary_router, secondary_iface)

        if primary_reachable:
            self._failover.primary_failures = 0
            self._failover.primary_successes += 1
        else:
            self._failover.primary_successes = 0
            self._failover.primary_failures += 1

        if secondary_reachable:
            self._failover.secondary_failures = 0
            self._failover.secondary_successes += 1
        else:
            self._failover.secondary_successes = 0
            self._failover.secondary_failures += 1

        if (
            self._failover.active_iface == primary_iface
            and self._failover.primary_failures >= self._settings.runtime_failover_threshold
            and secondary_reachable
        ):
            self._failover.active_iface = secondary_iface
            _logger.warning(
                "runtime.wg.failover",
                "Switched active route to secondary interface",
                from_iface=primary_iface,
                to_iface=secondary_iface,
                failures=self._failover.primary_failures,
            )
        elif (
            self._failover.active_iface == secondary_iface
            and self._settings.runtime_failback_enabled
            and self._failover.primary_successes >= self._settings.runtime_failback_stable_count
            and primary_reachable
        ):
            self._failover.active_iface = primary_iface
            _logger.info(
                "runtime.wg.failback",
                "Switched active route back to primary interface",
                from_iface=secondary_iface,
                to_iface=primary_iface,
                stable_successes=self._failover.primary_successes,
            )

        # Enforce route preferences every reconcile so primary/secondary metrics
        # are present from startup and remain corrected after drift.
        self._apply_route_preferences()

        return {
            "agent_last_reconcile_at": _utcnow_iso(),
            "agent_runtime_enabled": True,
            "wg_primary_tunnel": "up" if primary_up else "down",
            "wg_secondary_tunnel": "up" if secondary_up else "down",
            "wg_primary_router_reachable": primary_reachable,
            "wg_secondary_router_reachable": secondary_reachable,
            "wg_active_route": self._failover.active_iface,
            "wg_failover_state": "primary"
            if self._failover.active_iface == primary_iface
            else "secondary",
        }

    def _interface_exists(self, iface: str) -> bool:
        if not iface:
            return False
        code, _, _ = _run_command(("ip", "link", "show", "dev", iface))
        return code == 0

    def _router_reachable(self, router_ip: str, iface: str) -> bool:
        if not iface:
            return False
        if not router_ip:
            return self._interface_exists(iface)
        code, _, _ = _run_command(("ping", "-I", iface, "-c", "1", "-W", "1", router_ip))
        return code == 0

    def _apply_route_preferences(self) -> None:
        mesh_cidr = self._settings.runtime_mesh_cidr.strip()
        if not mesh_cidr:
            return

        primary_iface = self._settings.runtime_wg_primary_iface
        secondary_iface = self._settings.runtime_wg_secondary_iface
        primary_metric = self._settings.runtime_route_primary_metric
        secondary_metric = self._settings.runtime_route_secondary_metric
        if self._failover.active_iface == secondary_iface:
            primary_metric, secondary_metric = secondary_metric, primary_metric

        cmds = [
            (
                "ip",
                "route",
                "replace",
                mesh_cidr,
                "dev",
                primary_iface,
                "metric",
                str(primary_metric),
            ),
            (
                "ip",
                "route",
                "replace",
                mesh_cidr,
                "dev",
                secondary_iface,
                "metric",
                str(secondary_metric),
            ),
        ]
        for cmd in cmds:
            code, _, stderr = _run_command(cmd)
            if code != 0:
                now = time.time()
                if now - self._missing_tools_logged_at > 60:
                    _logger.warning(
                        "runtime.wg.route_error",
                        "Failed to apply route preference",
                        command=" ".join(cmd),
                        error=stderr,
                    )
                    self._missing_tools_logged_at = now

    async def _send_heartbeat(self, status_patch: Dict[str, Any]) -> None:
        identity_paths = self._identity_paths()
        key_path = identity_paths["key"]
        lease_path = identity_paths["lease"]
        if not key_path.exists() or not lease_path.exists():
            now = time.time()
            if now - self._missing_identity_logged_at > 60:
                _logger.warning(
                    "runtime.agent.identity_missing",
                    "Identity artifacts are missing; heartbeat skipped",
                    node_id=self._settings.runtime_node_id,
                    key_path=str(key_path),
                    lease_path=str(lease_path),
                )
                self._missing_identity_logged_at = now
            return

        lease_token = lease_path.read_text(encoding="utf-8").strip()
        private_key_pem = key_path.read_bytes()
        signed_at = int(time.time())
        message = heartbeat_signing_message(
            node_id=self._settings.runtime_node_id,
            lease_token=lease_token,
            signed_at=signed_at,
            ttl_seconds=self._settings.runtime_heartbeat_ttl_seconds,
            status_patch=status_patch,
        )
        signature = _sign_heartbeat(private_key_pem, message)
        payload = {
            "node_id": self._settings.runtime_node_id,
            "lease_token": lease_token,
            "ttl_seconds": self._settings.runtime_heartbeat_ttl_seconds,
            "status_patch": status_patch,
            "signed_at": signed_at,
            "signature": signature,
        }
        url = f"{self._settings.runtime_api_base_url.rstrip('/')}/cluster/heartbeat"
        try:
            await asyncio.to_thread(
                _http_json,
                url,
                method="POST",
                payload=payload,
                timeout_seconds=6,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "runtime.agent.heartbeat_error",
                "Heartbeat publish failed",
                node_id=self._settings.runtime_node_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return

        await self._upsert_node_runtime_metadata(status_patch)
        _logger.info(
            "runtime.agent.heartbeat_ok",
            "Published signed heartbeat",
            node_id=self._settings.runtime_node_id,
            active_route=status_patch.get("wg_active_route"),
            failover_state=status_patch.get("wg_failover_state"),
        )

    async def _upsert_cluster_settings(self, updates: Dict[str, str]) -> bool:
        changed = False
        async with self._sessionmaker() as session:
            for key, value in updates.items():
                row = await session.get(ClusterSetting, key)
                if row is None:
                    session.add(ClusterSetting(key=key, value=value))
                    changed = True
                elif row.value != value:
                    row.value = value
                    changed = True
            if changed:
                await session.commit()
        return changed

    async def _upsert_node_runtime_metadata(self, status_patch: Dict[str, Any]) -> None:
        async with self._sessionmaker() as session:
            node = await session.get(Node, self._settings.runtime_node_id)
            if node is None:
                return
            status = dict(node.status or {})
            status.update(status_patch)
            node.status = status
            await session.commit()
