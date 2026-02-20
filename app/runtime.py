from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
from urllib import error, request

from app.config import Settings
from app.dependencies import get_sessionmaker
from app.logger import get_logger
from app.metrics import record_runtime_loop
from app.security import SESSION_COOKIE_NAME
from app.services import cluster_settings as cluster_settings_service
from app.services import discovery as discovery_service
from app.services import events as events_service
from app.services import gateway as gateway_service
from app.services import monitoring as monitoring_service
from app.services import scheduler as scheduler_service
from app.services import snapshots as snapshot_service
from app.schemas.snapshots import SnapshotRunCreate

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


def _http_status(url: str, *, timeout_seconds: int = 5) -> int:
    req = request.Request(url=url, method="GET")
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            return int(getattr(response, "status", 0))
    except error.HTTPError as exc:
        return int(exc.code)


class RuntimeController:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []
        self._sessionmaker = get_sessionmaker(settings.database_url)
        self._discovery_zone_sha = ""
        self._discovery_corefile_sha = ""
        self._gateway_config_sha = ""
        self._monitoring_config_sha = ""

    @property
    def enabled(self) -> bool:
        return bool(
            self._settings.runtime_enable
            or self._settings.runtime_etcd_endpoints.strip()
            or self._settings.runtime_discovery_enable
            or self._settings.runtime_gateway_enable
            or self._settings.runtime_monitoring_enable
            or self._settings.runtime_scheduler_plan_cache_enable
            or self._settings.runtime_events_prune_enable
            or (
                self._settings.etcd_snapshot_schedule_enabled
                and self._settings.etcd_enabled
                and self._settings.etcd_endpoints.strip()
            )
        )

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
                corefile_path=self._settings.runtime_discovery_corefile_path,
                listen=self._settings.runtime_discovery_listen,
                interval_seconds=self._settings.runtime_discovery_interval_seconds,
            )

        if self._settings.runtime_gateway_enable:
            self._tasks.append(asyncio.create_task(self._gateway_config_loop()))
            _logger.info(
                "runtime.gateway.start",
                "Started NGINX gateway config loop",
                config_path=self._settings.runtime_gateway_config_path,
                listen=self._settings.runtime_gateway_listen,
                interval_seconds=self._settings.runtime_gateway_interval_seconds,
            )

        if self._settings.runtime_monitoring_enable:
            self._tasks.append(asyncio.create_task(self._monitoring_config_loop()))
            _logger.info(
                "runtime.monitoring.start",
                "Started monitoring config loop",
                config_path=self._settings.runtime_monitoring_prometheus_config_path,
                interval_seconds=self._settings.runtime_monitoring_interval_seconds,
            )

        if (
            self._settings.etcd_snapshot_schedule_enabled
            and self._settings.etcd_enabled
            and self._settings.etcd_endpoints.strip()
        ):
            self._tasks.append(asyncio.create_task(self._snapshot_schedule_loop()))
            _logger.info(
                "runtime.snapshot.start",
                "Started scheduled snapshot loop",
                interval_seconds=self._settings.etcd_snapshot_interval_seconds,
                requested_by=self._settings.etcd_snapshot_schedule_requested_by,
            )

        if self._settings.runtime_events_prune_enable:
            self._tasks.append(asyncio.create_task(self._events_prune_loop()))
            _logger.info(
                "runtime.events.start",
                "Started event retention prune loop",
                retention_days=self._settings.events_retention_days,
                interval_seconds=self._settings.runtime_events_prune_interval_seconds,
                batch_size=self._settings.runtime_events_prune_batch_size,
            )

        if self._settings.runtime_scheduler_plan_cache_enable:
            self._tasks.append(asyncio.create_task(self._scheduler_plan_cache_loop()))
            _logger.info(
                "runtime.scheduler.start",
                "Started scheduler plan cache loop",
                interval_seconds=self._settings.runtime_scheduler_plan_cache_interval_seconds,
                service_limit=self._settings.runtime_scheduler_plan_cache_service_limit,
            )

        if self._settings.runtime_enable:
            _logger.warning(
                "runtime.agent.deprecated",
                "Python node agent loop is disabled; Go agent is the canonical runtime",
                runtime_enable=self._settings.runtime_enable,
                go_agent_binary="agent/cmd/uptimemesh-agent",
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
                changed, zone_changed, corefile_changed, services, endpoints = (
                    await self._sync_discovery_artifacts()
                )
                record_runtime_loop(loop="discovery_zone", ok=True)
                if changed:
                    _logger.info(
                        "runtime.discovery.sync",
                        "Updated discovery artifacts from healthy endpoint registry",
                        zone_path=self._settings.runtime_discovery_zone_path,
                        zone_changed=zone_changed,
                        corefile_path=self._settings.runtime_discovery_corefile_path,
                        corefile_changed=corefile_changed,
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

    def _write_discovery_text(self, *, path: Path, text: str, previous_sha: str) -> tuple[bool, str]:
        data = text.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        if digest == previous_sha and path.exists():
            return False, digest

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_bytes(data)
        os.replace(tmp_path, path)
        return True, digest

    async def _sync_discovery_artifacts(self) -> tuple[bool, bool, bool, int, int]:
        async with self._sessionmaker() as session:
            zone_text, service_count, endpoint_count = await discovery_service.render_zone_file(
                session,
                domain=self._settings.runtime_discovery_domain,
                ttl_seconds=self._settings.runtime_discovery_ttl_seconds,
            )
        corefile_text = discovery_service.render_corefile(
            domain=self._settings.runtime_discovery_domain,
            zone_file_path=self._settings.runtime_discovery_zone_path,
            listen=self._settings.runtime_discovery_listen,
            forwarders=self._settings.runtime_discovery_forwarders,
        )

        zone_path = Path(self._settings.runtime_discovery_zone_path)
        zone_changed, zone_sha = self._write_discovery_text(
            path=zone_path,
            text=zone_text,
            previous_sha=self._discovery_zone_sha,
        )
        self._discovery_zone_sha = zone_sha

        corefile_path = Path(self._settings.runtime_discovery_corefile_path)
        corefile_changed, corefile_sha = self._write_discovery_text(
            path=corefile_path,
            text=corefile_text,
            previous_sha=self._discovery_corefile_sha,
        )
        self._discovery_corefile_sha = corefile_sha
        changed = zone_changed or corefile_changed

        if changed:
            await self._upsert_cluster_settings(
                {
                    "discovery_domain": self._settings.runtime_discovery_domain,
                    "discovery_zone_path": self._settings.runtime_discovery_zone_path,
                    "discovery_corefile_path": self._settings.runtime_discovery_corefile_path,
                    "discovery_zone_sha256": zone_sha,
                    "discovery_corefile_sha256": corefile_sha,
                    "discovery_service_count": str(service_count),
                    "discovery_endpoint_count": str(endpoint_count),
                    "discovery_last_sync_at": _utcnow_iso(),
                }
            )

            reload_cmd = self._settings.runtime_discovery_reload_command.strip()
            if reload_cmd:
                code, out, err = _run_command(("sh", "-c", reload_cmd))
                if code != 0:
                    _logger.warning(
                        "runtime.discovery.reload_error",
                        "Failed to reload CoreDNS after discovery update",
                        command=reload_cmd,
                        error=err or out or f"exit_{code}",
                    )
                else:
                    _logger.info(
                        "runtime.discovery.reload_ok",
                        "Reloaded CoreDNS after discovery update",
                        command=reload_cmd,
                    )
        return changed, zone_changed, corefile_changed, service_count, endpoint_count

    def _write_bytes_atomic(self, *, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_bytes(data)
        os.replace(tmp_path, path)

    def _gateway_healthcheck_urls(self) -> list[str]:
        return [
            item.strip()
            for item in self._settings.runtime_gateway_healthcheck_urls.split(",")
            if item.strip()
        ]

    def _format_gateway_command(
        self,
        template: str,
        *,
        config_path: Path,
        candidate_path: Path,
        backup_path: Path,
    ) -> str:
        command = template.strip()
        if not command:
            return ""
        return (
            command.replace("{config_path}", shlex.quote(str(config_path)))
            .replace("{candidate_path}", shlex.quote(str(candidate_path)))
            .replace("{backup_path}", shlex.quote(str(backup_path)))
        )

    async def _mark_gateway_status(
        self,
        *,
        status: str,
        error_text: str,
        route_count: int,
        upstream_count: int,
        digest: str = "",
    ) -> None:
        await self._upsert_cluster_settings(
            {
                "gateway_last_apply_status": status,
                "gateway_last_apply_error": error_text,
                "gateway_last_sync_at": _utcnow_iso(),
                "gateway_route_count": str(route_count),
                "gateway_upstream_count": str(upstream_count),
                "gateway_config_sha256": digest,
                "gateway_config_path": self._settings.runtime_gateway_config_path,
            }
        )

    async def _mark_monitoring_status(
        self,
        *,
        status: str,
        error_text: str,
        digest: str,
        api_targets: list[str],
        node_exporter_targets: list[str],
        alertmanager_targets: list[str],
    ) -> None:
        await self._upsert_cluster_settings(
            {
                "monitoring_last_apply_status": status,
                "monitoring_last_apply_error": error_text,
                "monitoring_last_sync_at": _utcnow_iso(),
                "monitoring_config_sha256": digest,
                "monitoring_config_path": self._settings.runtime_monitoring_prometheus_config_path,
                "monitoring_api_target_count": str(len(api_targets)),
                "monitoring_node_exporter_target_count": str(len(node_exporter_targets)),
                "monitoring_alertmanager_target_count": str(len(alertmanager_targets)),
                "monitoring_api_targets": ",".join(api_targets),
                "monitoring_node_exporter_targets": ",".join(node_exporter_targets),
                "monitoring_alertmanager_targets": ",".join(alertmanager_targets),
            }
        )

    async def _gateway_config_loop(self) -> None:
        interval = self._settings.runtime_gateway_interval_seconds
        while not self._stop.is_set():
            try:
                changed, routes, upstreams = await self._sync_gateway_config()
                record_runtime_loop(loop="gateway_config", ok=True)
                if changed:
                    _logger.info(
                        "runtime.gateway.sync",
                        "Applied NGINX gateway configuration safely",
                        config_path=self._settings.runtime_gateway_config_path,
                        routes=routes,
                        upstreams=upstreams,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="gateway_config", ok=False)
                _logger.exception(
                    "runtime.gateway.error",
                    "Gateway config sync failed",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _sync_gateway_config(self) -> tuple[bool, int, int]:
        async with self._sessionmaker() as session:
            rendered = await gateway_service.render_gateway_config(
                session,
                listen=self._settings.runtime_gateway_listen,
                default_server_name=self._settings.runtime_gateway_server_name,
            )

        config_text = rendered.config
        route_count = rendered.route_count
        upstream_count = rendered.upstream_count
        config_data = config_text.encode("utf-8")
        digest = hashlib.sha256(config_data).hexdigest()

        config_path, candidate_path, backup_path = gateway_service.resolve_gateway_paths(
            config_path=self._settings.runtime_gateway_config_path,
            candidate_path=self._settings.runtime_gateway_candidate_path,
            backup_path=self._settings.runtime_gateway_backup_path,
        )

        if digest == self._gateway_config_sha and config_path.exists():
            return False, route_count, upstream_count

        self._write_bytes_atomic(path=candidate_path, data=config_data)
        _logger.info(
            "runtime.gateway.candidate",
            "Wrote candidate NGINX config",
            candidate_path=str(candidate_path),
            routes=route_count,
            upstreams=upstream_count,
        )

        validate_template = self._settings.runtime_gateway_validate_command
        validate_command = self._format_gateway_command(
            validate_template,
            config_path=candidate_path,
            candidate_path=candidate_path,
            backup_path=backup_path,
        )
        if validate_command:
            code, out, err = _run_command(("sh", "-c", validate_command))
            if code != 0:
                error_text = err or out or f"exit_{code}"
                await self._mark_gateway_status(
                    status="validate_failed",
                    error_text=error_text,
                    route_count=route_count,
                    upstream_count=upstream_count,
                    digest=self._gateway_config_sha,
                )
                raise RuntimeError(f"gateway validation failed: {error_text}")

        previous_config: bytes | None = None
        if config_path.exists():
            previous_config = config_path.read_bytes()
            self._write_bytes_atomic(path=backup_path, data=previous_config)

        self._write_bytes_atomic(path=config_path, data=config_data)

        reload_template = self._settings.runtime_gateway_reload_command
        reload_command = self._format_gateway_command(
            reload_template,
            config_path=config_path,
            candidate_path=candidate_path,
            backup_path=backup_path,
        )
        if reload_command:
            code, out, err = _run_command(("sh", "-c", reload_command))
            if code != 0:
                error_text = err or out or f"exit_{code}"
                if previous_config is not None:
                    self._write_bytes_atomic(path=config_path, data=previous_config)
                    _run_command(("sh", "-c", reload_command))
                await self._mark_gateway_status(
                    status="reload_failed",
                    error_text=error_text,
                    route_count=route_count,
                    upstream_count=upstream_count,
                    digest=self._gateway_config_sha,
                )
                raise RuntimeError(f"gateway reload failed: {error_text}")

        healthcheck_urls = self._gateway_healthcheck_urls()
        expected_status = self._settings.runtime_gateway_healthcheck_expected_status
        timeout_seconds = self._settings.runtime_gateway_healthcheck_timeout_seconds
        for url in healthcheck_urls:
            try:
                status_code = await asyncio.to_thread(
                    _http_status,
                    url,
                    timeout_seconds=timeout_seconds,
                )
            except Exception as exc:  # noqa: BLE001
                error_text = f"healthcheck exception for {url}: {type(exc).__name__}: {exc}"
                if previous_config is not None:
                    self._write_bytes_atomic(path=config_path, data=previous_config)
                    if reload_command:
                        _run_command(("sh", "-c", reload_command))
                await self._mark_gateway_status(
                    status="healthcheck_failed",
                    error_text=error_text,
                    route_count=route_count,
                    upstream_count=upstream_count,
                    digest=self._gateway_config_sha,
                )
                raise RuntimeError(f"gateway post-reload healthcheck failed: {error_text}") from exc

            if status_code != expected_status:
                error_text = f"healthcheck status {status_code} for {url} (expected {expected_status})"
                if previous_config is not None:
                    self._write_bytes_atomic(path=config_path, data=previous_config)
                    if reload_command:
                        _run_command(("sh", "-c", reload_command))
                await self._mark_gateway_status(
                    status="healthcheck_failed",
                    error_text=error_text,
                    route_count=route_count,
                    upstream_count=upstream_count,
                    digest=self._gateway_config_sha,
                )
                raise RuntimeError(f"gateway post-reload healthcheck failed: {error_text}")

        self._gateway_config_sha = digest
        await self._mark_gateway_status(
            status="ok",
            error_text="",
            route_count=route_count,
            upstream_count=upstream_count,
            digest=digest,
        )
        return True, route_count, upstream_count

    async def _monitoring_config_loop(self) -> None:
        interval = self._settings.runtime_monitoring_interval_seconds
        while not self._stop.is_set():
            try:
                changed, api_targets, node_exporter_targets, alertmanager_targets = (
                    await self._sync_monitoring_config()
                )
                record_runtime_loop(loop="monitoring_config", ok=True)
                if changed:
                    _logger.info(
                        "runtime.monitoring.sync",
                        "Applied Prometheus monitoring config",
                        config_path=self._settings.runtime_monitoring_prometheus_config_path,
                        api_targets=api_targets,
                        node_exporter_targets=node_exporter_targets,
                        alertmanager_targets=alertmanager_targets,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="monitoring_config", ok=False)
                _logger.exception(
                    "runtime.monitoring.error",
                    "Monitoring config sync failed",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _sync_monitoring_config(self) -> tuple[bool, int, int, int]:
        async with self._sessionmaker() as session:
            rendered = await monitoring_service.render_prometheus_config(
                session,
                app_metrics_path="/metrics",
                default_api_port=self._settings.server_port,
                node_exporter_port=self._settings.runtime_monitoring_node_exporter_port,
                scrape_interval_seconds=self._settings.runtime_monitoring_scrape_interval_seconds,
                evaluation_interval_seconds=self._settings.runtime_monitoring_evaluation_interval_seconds,
                rules_path=self._settings.runtime_monitoring_rules_path,
                alertmanager_targets_raw=self._settings.runtime_monitoring_alertmanager_targets,
                include_localhost_targets=self._settings.runtime_monitoring_include_localhost_targets,
            )

        config_data = rendered.config.encode("utf-8")
        digest = hashlib.sha256(config_data).hexdigest()
        paths = monitoring_service.resolve_monitoring_paths(
            config_path=self._settings.runtime_monitoring_prometheus_config_path,
            candidate_path=self._settings.runtime_monitoring_prometheus_candidate_path,
            backup_path=self._settings.runtime_monitoring_prometheus_backup_path,
        )

        if digest == self._monitoring_config_sha and paths.config_path.exists():
            return (
                False,
                len(rendered.api_targets),
                len(rendered.node_exporter_targets),
                len(rendered.alertmanager_targets),
            )

        self._write_bytes_atomic(path=paths.candidate_path, data=config_data)
        _logger.info(
            "runtime.monitoring.candidate",
            "Wrote candidate Prometheus config",
            candidate_path=str(paths.candidate_path),
            api_targets=len(rendered.api_targets),
            node_exporter_targets=len(rendered.node_exporter_targets),
            alertmanager_targets=len(rendered.alertmanager_targets),
        )

        validate_command = self._format_gateway_command(
            self._settings.runtime_monitoring_validate_command,
            config_path=paths.config_path,
            candidate_path=paths.candidate_path,
            backup_path=paths.backup_path,
        )
        if validate_command:
            code, out, err = _run_command(("sh", "-c", validate_command))
            if code != 0:
                error_text = err or out or f"exit_{code}"
                await self._mark_monitoring_status(
                    status="validate_failed",
                    error_text=error_text,
                    digest=self._monitoring_config_sha,
                    api_targets=rendered.api_targets,
                    node_exporter_targets=rendered.node_exporter_targets,
                    alertmanager_targets=rendered.alertmanager_targets,
                )
                raise RuntimeError(f"monitoring validation failed: {error_text}")

        previous_config: bytes | None = None
        if paths.config_path.exists():
            previous_config = paths.config_path.read_bytes()
            self._write_bytes_atomic(path=paths.backup_path, data=previous_config)
        self._write_bytes_atomic(path=paths.config_path, data=config_data)

        reload_command = self._format_gateway_command(
            self._settings.runtime_monitoring_reload_command,
            config_path=paths.config_path,
            candidate_path=paths.candidate_path,
            backup_path=paths.backup_path,
        )
        if reload_command:
            code, out, err = _run_command(("sh", "-c", reload_command))
            if code != 0:
                error_text = err or out or f"exit_{code}"
                if previous_config is not None:
                    self._write_bytes_atomic(path=paths.config_path, data=previous_config)
                    _run_command(("sh", "-c", reload_command))
                await self._mark_monitoring_status(
                    status="reload_failed",
                    error_text=error_text,
                    digest=self._monitoring_config_sha,
                    api_targets=rendered.api_targets,
                    node_exporter_targets=rendered.node_exporter_targets,
                    alertmanager_targets=rendered.alertmanager_targets,
                )
                raise RuntimeError(f"monitoring reload failed: {error_text}")

        self._monitoring_config_sha = digest
        await self._mark_monitoring_status(
            status="ok",
            error_text="",
            digest=digest,
            api_targets=rendered.api_targets,
            node_exporter_targets=rendered.node_exporter_targets,
            alertmanager_targets=rendered.alertmanager_targets,
        )

        return (
            True,
            len(rendered.api_targets),
            len(rendered.node_exporter_targets),
            len(rendered.alertmanager_targets),
        )

    async def _snapshot_schedule_loop(self) -> None:
        interval = self._settings.etcd_snapshot_interval_seconds
        requested_by = self._settings.etcd_snapshot_schedule_requested_by
        while not self._stop.is_set():
            try:
                now = datetime.now(timezone.utc)
                should_run = True
                age_seconds = -1.0
                latest_id = ""

                async with self._sessionmaker() as session:
                    latest = await snapshot_service.list_snapshots(session, limit=1)
                    if latest:
                        item = latest[0]
                        latest_id = item.id
                        created_at = item.created_at
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=timezone.utc)
                        age_seconds = max(
                            0.0,
                            (now - created_at.astimezone(timezone.utc)).total_seconds(),
                        )
                        if item.status == "running":
                            should_run = False
                        elif age_seconds < interval:
                            should_run = False

                    if should_run:
                        snapshot_id = f"auto-{now.strftime('%Y%m%d%H%M%S')}"
                        result = await snapshot_service.create_snapshot(
                            session,
                            SnapshotRunCreate(id=snapshot_id, requested_by=requested_by),
                        )
                        _logger.info(
                            "runtime.snapshot.run",
                            "Executed scheduled etcd snapshot",
                            snapshot_id=result.id,
                            status=result.status,
                            requested_by=requested_by,
                            location=result.location or "",
                        )
                    else:
                        _logger.debug(
                            "runtime.snapshot.skip",
                            "Skipped scheduled snapshot (interval not reached)",
                            interval_seconds=interval,
                            latest_snapshot_id=latest_id,
                            latest_age_seconds=round(age_seconds, 1),
                        )
                record_runtime_loop(loop="snapshot_schedule", ok=True)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="snapshot_schedule", ok=False)
                _logger.exception(
                    "runtime.snapshot.error",
                    "Scheduled snapshot loop failed",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _scheduler_plan_cache_loop(self) -> None:
        interval = self._settings.runtime_scheduler_plan_cache_interval_seconds
        service_limit = self._settings.runtime_scheduler_plan_cache_service_limit
        while not self._stop.is_set():
            try:
                async with self._sessionmaker() as session:
                    plan = await scheduler_service.refresh_cached_plan(
                        session,
                        limit=service_limit,
                    )
                record_runtime_loop(loop="scheduler_plan_cache", ok=True)
                _logger.debug(
                    "runtime.scheduler.cache_refresh",
                    "Refreshed scheduler dry-run cache",
                    service_count=len(plan.results),
                    generated_at=plan.generated_at.isoformat(),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="scheduler_plan_cache", ok=False)
                _logger.exception(
                    "runtime.scheduler.cache_error",
                    "Failed to refresh scheduler dry-run cache",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _events_prune_loop(self) -> None:
        interval = self._settings.runtime_events_prune_interval_seconds
        retention_days = self._settings.events_retention_days
        batch_size = self._settings.runtime_events_prune_batch_size
        while not self._stop.is_set():
            try:
                async with self._sessionmaker() as session:
                    deleted = await events_service.prune_old_events(
                        session,
                        retention_days=retention_days,
                        batch_size=batch_size,
                    )
                record_runtime_loop(loop="events_prune", ok=True)
                _logger.debug(
                    "runtime.events.prune",
                    "Applied event retention pruning pass",
                    deleted=deleted,
                    retention_days=retention_days,
                    batch_size=batch_size,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                record_runtime_loop(loop="events_prune", ok=False)
                _logger.exception(
                    "runtime.events.error",
                    "Event retention prune loop failed",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                continue

    async def _upsert_cluster_settings(self, updates: Dict[str, str]) -> bool:
        async with self._sessionmaker() as session:
            return await cluster_settings_service.upsert_settings(
                session,
                updates,
                sync_file=True,
            )
