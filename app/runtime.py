from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib import error, request
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from sqlalchemy import select

from app.config import Settings
from app.dependencies import get_sessionmaker
from app.identity import heartbeat_signing_message
from app.logger import get_logger
from app.metrics import record_runtime_loop
from app.models.node import Node
from app.models.router_assignment import RouterAssignment
from app.security import SESSION_COOKIE_NAME
from app.services import cluster_settings as cluster_settings_service
from app.services import discovery as discovery_service

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
    try:
        process = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)
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


@dataclass
class _WireGuardPeerIntent:
    public_key: str = ""
    endpoint: str = ""
    allowed_ips: str = ""
    persistent_keepalive: int = 0
    router_ip: str = ""


@dataclass
class _WireGuardIntent:
    local_address: str = ""
    primary: _WireGuardPeerIntent = field(default_factory=_WireGuardPeerIntent)
    secondary: _WireGuardPeerIntent = field(default_factory=_WireGuardPeerIntent)


class RuntimeController:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []
        self._sessionmaker = get_sessionmaker(settings.database_url)
        self._failover = _FailoverState(active_iface=settings.runtime_wg_primary_iface)
        self._missing_identity_logged_at = 0.0
        self._missing_tools_logged_at = 0.0
        self._discovery_zone_sha = ""

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

        if self._settings.runtime_discovery_enable:
            self._tasks.append(asyncio.create_task(self._discovery_zone_loop()))
            _logger.info(
                "runtime.discovery.start",
                "Started discovery zone loop",
                domain=self._settings.runtime_discovery_domain,
                zone_path=self._settings.runtime_discovery_zone_path,
                interval_seconds=self._settings.runtime_discovery_interval_seconds,
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
                record_runtime_loop(loop="etcd_probe", ok=status == "ok")
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

    async def _discovery_zone_loop(self) -> None:
        interval = self._settings.runtime_discovery_interval_seconds
        while not self._stop.is_set():
            try:
                changed, services, endpoints = await self._sync_discovery_zone()
                record_runtime_loop(loop="discovery_zone", ok=True)
                if changed:
                    _logger.info(
                        "runtime.discovery.sync",
                        "Updated CoreDNS zone from endpoint registry",
                        zone_path=self._settings.runtime_discovery_zone_path,
                        services=services,
                        endpoints=endpoints,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="discovery_zone", ok=False)
                _logger.exception(
                    "runtime.discovery.error",
                    "Discovery zone sync failed",
                    error_type=type(exc).__name__,
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _sync_discovery_zone(self) -> tuple[bool, int, int]:
        async with self._sessionmaker() as session:
            zone_text, service_count, endpoint_count = await discovery_service.render_zone_file(
                session,
                domain=self._settings.runtime_discovery_domain,
                ttl_seconds=self._settings.runtime_discovery_ttl_seconds,
            )

        data = zone_text.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        if digest == self._discovery_zone_sha:
            return False, service_count, endpoint_count

        zone_path = Path(self._settings.runtime_discovery_zone_path)
        zone_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = zone_path.with_suffix(f"{zone_path.suffix}.tmp")
        tmp_path.write_bytes(data)
        os.replace(tmp_path, zone_path)
        self._discovery_zone_sha = digest

        reload_cmd = self._settings.runtime_discovery_reload_command.strip()
        if reload_cmd:
            code, out, err = _run_command(("sh", "-c", reload_cmd))
            if code != 0:
                _logger.warning(
                    "runtime.discovery.reload_error",
                    "Failed to reload CoreDNS after zone update",
                    command=reload_cmd,
                    error=err or out or f"exit_{code}",
                )
            else:
                _logger.info(
                    "runtime.discovery.reload_ok",
                    "Reloaded CoreDNS after zone update",
                    command=reload_cmd,
                )
        return True, service_count, endpoint_count

    async def _node_agent_loop(self) -> None:
        interval = self._settings.runtime_heartbeat_interval_seconds
        while not self._stop.is_set():
            try:
                wg_intent = await self._load_wireguard_intent()
                status_patch = await asyncio.to_thread(self._reconcile_wireguard_state, wg_intent)
                await self._send_heartbeat(status_patch)
                record_runtime_loop(loop="node_agent", ok=True)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="node_agent", ok=False)
                _logger.exception(
                    "runtime.agent.error",
                    "Node runtime loop failed",
                    error_type=type(exc).__name__,
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _load_wireguard_intent(self) -> _WireGuardIntent:
        allowed_ips = self._settings.runtime_wg_peer_allowed_ips.strip() or self._settings.runtime_mesh_cidr
        intent = _WireGuardIntent(
            local_address=self._normalize_address(self._settings.runtime_wg_local_address.strip()),
            primary=_WireGuardPeerIntent(
                public_key=self._settings.runtime_wg_primary_peer_public_key.strip(),
                endpoint=self._settings.runtime_wg_primary_peer_endpoint.strip(),
                allowed_ips=allowed_ips,
                persistent_keepalive=self._settings.runtime_wg_persistent_keepalive_seconds,
                router_ip=self._settings.runtime_wg_primary_router_ip.strip(),
            ),
            secondary=_WireGuardPeerIntent(
                public_key=self._settings.runtime_wg_secondary_peer_public_key.strip(),
                endpoint=self._settings.runtime_wg_secondary_peer_endpoint.strip(),
                allowed_ips=allowed_ips,
                persistent_keepalive=self._settings.runtime_wg_persistent_keepalive_seconds,
                router_ip=self._settings.runtime_wg_secondary_router_ip.strip(),
            ),
        )

        async with self._sessionmaker() as session:
            local_node = await session.get(Node, self._settings.runtime_node_id)
            if local_node is not None:
                if not intent.local_address:
                    intent.local_address = self._normalize_address(local_node.mesh_ip or "")

                result = await session.execute(
                    select(RouterAssignment)
                    .where(RouterAssignment.node_id == local_node.id)
                    .limit(1)
                )
                assignment = result.scalar_one_or_none()
                if assignment is None:
                    return intent

                primary_router = await session.get(Node, assignment.primary_router_id)
                secondary_router = await session.get(Node, assignment.secondary_router_id)

                if primary_router is not None:
                    self._merge_router_intent(
                        peer=intent.primary,
                        router=primary_router,
                        preferred_key_fields=("wg_primary_public_key", "wg_public_key"),
                    )
                if secondary_router is not None:
                    self._merge_router_intent(
                        peer=intent.secondary,
                        router=secondary_router,
                        preferred_key_fields=("wg_secondary_public_key", "wg_public_key"),
                    )

        return intent

    def _identity_paths(self) -> dict[str, Path]:
        root = Path(self._settings.runtime_identity_dir) / self._settings.runtime_node_id
        return {
            "key": root / "node.key",
            "lease": root / "lease.token",
        }

    def _merge_router_intent(
        self,
        *,
        peer: _WireGuardPeerIntent,
        router: Node,
        preferred_key_fields: tuple[str, ...],
    ) -> None:
        status = router.status if isinstance(router.status, dict) else {}
        if not peer.public_key:
            for key_field in preferred_key_fields:
                value = status.get(key_field)
                if isinstance(value, str) and value.strip():
                    peer.public_key = value.strip()
                    break

        if not peer.endpoint:
            endpoint = status.get("wg_endpoint")
            if isinstance(endpoint, str) and endpoint.strip():
                peer.endpoint = endpoint.strip()
            else:
                peer.endpoint = self._endpoint_from_api(router.api_endpoint)

        if not peer.router_ip and router.mesh_ip:
            peer.router_ip = router.mesh_ip.strip()

    def _normalize_address(self, value: str) -> str:
        raw = value.strip()
        if not raw:
            return ""
        if "/" in raw:
            return raw
        return f"{raw}/32"

    def _endpoint_from_api(self, api_endpoint: str | None) -> str:
        if not api_endpoint:
            return ""
        try:
            parsed = urlparse(api_endpoint)
        except Exception:  # noqa: BLE001
            return ""
        if not parsed.hostname:
            return ""
        port = parsed.port or self._settings.runtime_wg_peer_port
        return f"{parsed.hostname}:{port}"

    def _reconcile_wireguard_state(self, intent: _WireGuardIntent) -> Dict[str, Any]:
        primary_iface = self._settings.runtime_wg_primary_iface
        secondary_iface = self._settings.runtime_wg_secondary_iface
        primary_router = intent.primary.router_ip.strip()
        secondary_router = intent.secondary.router_ip.strip()

        primary_public_key = ""
        secondary_public_key = ""
        if self._settings.runtime_wg_configure:
            self._ensure_wireguard_interface(
                iface=primary_iface,
                listen_port=self._settings.runtime_wg_primary_listen_port,
                local_address=intent.local_address,
                peer=intent.primary,
            )
            self._ensure_wireguard_interface(
                iface=secondary_iface,
                listen_port=self._settings.runtime_wg_secondary_listen_port,
                local_address=intent.local_address,
                peer=intent.secondary,
            )
            primary_public_key = self._wireguard_public_key(primary_iface)
            secondary_public_key = self._wireguard_public_key(secondary_iface)

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
            "wg_primary_public_key": primary_public_key,
            "wg_secondary_public_key": secondary_public_key,
            "wg_public_key": primary_public_key or secondary_public_key,
            "wg_primary_peer_endpoint": intent.primary.endpoint,
            "wg_secondary_peer_endpoint": intent.secondary.endpoint,
            "wg_primary_peer_configured": bool(intent.primary.public_key),
            "wg_secondary_peer_configured": bool(intent.secondary.public_key),
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

    def _wireguard_key_path(self, iface: str) -> Path:
        key_dir = Path(self._settings.runtime_wg_key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        return key_dir / f"{iface}.key"

    def _ensure_wireguard_key(self, iface: str) -> Path | None:
        key_path = self._wireguard_key_path(iface)
        if key_path.exists() and key_path.stat().st_size > 0:
            return key_path

        code, out, err = _run_command(("wg", "genkey"))
        if code != 0 or not out:
            now = time.time()
            if now - self._missing_tools_logged_at > 60:
                _logger.warning(
                    "runtime.wg.genkey_error",
                    "Failed to generate WireGuard private key",
                    iface=iface,
                    error=err or out or f"exit_{code}",
                )
                self._missing_tools_logged_at = now
            return None

        key_path.write_text(f"{out.strip()}\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        _logger.info("runtime.wg.key_create", "Generated WireGuard private key", iface=iface)
        return key_path

    def _wireguard_public_key(self, iface: str) -> str:
        code, out, _ = _run_command(("wg", "show", iface, "public-key"))
        if code != 0:
            return ""
        return out.strip()

    def _wireguard_list_peers(self, iface: str) -> set[str]:
        code, out, _ = _run_command(("wg", "show", iface, "peers"))
        if code != 0:
            return set()
        return {line.strip() for line in out.splitlines() if line.strip()}

    def _ensure_wireguard_interface(
        self,
        *,
        iface: str,
        listen_port: int,
        local_address: str,
        peer: _WireGuardPeerIntent,
    ) -> None:
        if not iface:
            return
        if self._interface_exists(iface):
            self._configure_wireguard_iface(
                iface=iface,
                listen_port=listen_port,
                local_address=local_address,
                peer=peer,
            )
            return

        code, _, err = _run_command(("ip", "link", "add", "dev", iface, "type", "wireguard"))
        if code != 0:
            now = time.time()
            if now - self._missing_tools_logged_at > 60:
                _logger.warning(
                    "runtime.wg.iface_create_error",
                    "Failed to create WireGuard interface",
                    iface=iface,
                    error=err or f"exit_{code}",
                )
                self._missing_tools_logged_at = now
            return
        _logger.info("runtime.wg.iface_create", "Created WireGuard interface", iface=iface)
        self._configure_wireguard_iface(
            iface=iface,
            listen_port=listen_port,
            local_address=local_address,
            peer=peer,
        )

    def _configure_wireguard_iface(
        self,
        *,
        iface: str,
        listen_port: int,
        local_address: str,
        peer: _WireGuardPeerIntent,
    ) -> None:
        key_path = self._ensure_wireguard_key(iface)
        if key_path is None:
            return

        if listen_port > 0:
            wg_cmd = ("wg", "set", iface, "listen-port", str(listen_port), "private-key", str(key_path))
        else:
            wg_cmd = ("wg", "set", iface, "private-key", str(key_path))

        code, _, err = _run_command(wg_cmd)
        if code != 0:
            now = time.time()
            if now - self._missing_tools_logged_at > 60:
                _logger.warning(
                    "runtime.wg.set_error",
                    "Failed to configure WireGuard interface",
                    iface=iface,
                    error=err or f"exit_{code}",
                )
                self._missing_tools_logged_at = now
            return

        if local_address:
            _run_command(("ip", "-4", "address", "replace", local_address, "dev", iface))

        _run_command(("ip", "link", "set", "up", "dev", iface))
        self._sync_wireguard_peer(iface=iface, peer=peer)

    def _sync_wireguard_peer(self, *, iface: str, peer: _WireGuardPeerIntent) -> None:
        existing = self._wireguard_list_peers(iface)
        desired = {peer.public_key} if peer.public_key else set()
        for stale_peer in existing - desired:
            _run_command(("wg", "set", iface, "peer", stale_peer, "remove"))

        if not peer.public_key:
            return

        cmd = ["wg", "set", iface, "peer", peer.public_key]
        if peer.endpoint:
            cmd.extend(["endpoint", peer.endpoint])
        if peer.allowed_ips:
            cmd.extend(["allowed-ips", peer.allowed_ips])
        if peer.persistent_keepalive > 0:
            cmd.extend(["persistent-keepalive", str(peer.persistent_keepalive)])

        code, _, err = _run_command(tuple(cmd))
        if code != 0:
            _logger.warning(
                "runtime.wg.peer_error",
                "Failed to configure WireGuard peer",
                iface=iface,
                peer_endpoint=peer.endpoint,
                error=err or f"exit_{code}",
            )

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

        commands: list[tuple[str, tuple[str, ...]]] = [
            (
                primary_iface,
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
            ),
            (
                secondary_iface,
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
            ),
        ]
        for iface, cmd in commands:
            if not self._interface_exists(iface):
                continue
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
        async with self._sessionmaker() as session:
            return await cluster_settings_service.upsert_settings(
                session,
                updates,
                sync_file=True,
            )

    async def _upsert_node_runtime_metadata(self, status_patch: Dict[str, Any]) -> None:
        async with self._sessionmaker() as session:
            node = await session.get(Node, self._settings.runtime_node_id)
            if node is None:
                return
            status = dict(node.status or {})
            status.update(status_patch)
            node.status = status
            await session.commit()
