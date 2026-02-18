from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.node import Node

_logger = get_logger("services.monitoring")


@dataclass(frozen=True)
class PrometheusRenderResult:
    config: str
    api_targets: list[str]
    node_exporter_targets: list[str]
    alertmanager_targets: list[str]


@dataclass(frozen=True)
class MonitoringPaths:
    config_path: Path
    candidate_path: Path
    backup_path: Path


def _normalize_host(value: str) -> str:
    host = value.strip()
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host and not host.replace(":", "").isdigit() and not host.count(".") == 3:
        return f"[{host}]"
    return host


def _split_targets(raw: str) -> list[str]:
    values: list[str] = []
    for token in raw.replace(",", " ").split():
        candidate = token.strip()
        if candidate:
            values.append(candidate)
    return values


def _sorted_unique(items: set[str]) -> list[str]:
    return sorted(item for item in items if item)


def _target_from_endpoint(endpoint: str, default_port: int) -> tuple[str, int]:
    parsed = urlparse(endpoint)
    host = parsed.hostname or ""
    port = parsed.port or default_port
    return host, port


def _seconds_interval(value: int) -> str:
    safe = value if value > 0 else 15
    return f"{safe}s"


def resolve_monitoring_paths(
    *,
    config_path: str,
    candidate_path: str,
    backup_path: str,
) -> MonitoringPaths:
    resolved: list[Path] = []
    for raw in (config_path, candidate_path, backup_path):
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        resolved.append(path)
    return MonitoringPaths(
        config_path=resolved[0],
        candidate_path=resolved[1],
        backup_path=resolved[2],
    )


async def render_prometheus_config(
    session: AsyncSession,
    *,
    app_metrics_path: str,
    default_api_port: int,
    node_exporter_port: int,
    scrape_interval_seconds: int,
    evaluation_interval_seconds: int,
    rules_path: str,
    alertmanager_targets_raw: str,
    include_localhost_targets: bool,
) -> PrometheusRenderResult:
    async with _logger.operation(
        "monitoring.prometheus.render",
        "Rendering Prometheus config from registered nodes",
        metrics_path=app_metrics_path,
        default_api_port=default_api_port,
        node_exporter_port=node_exporter_port,
    ) as op:
        rows = (await session.execute(select(Node))).scalars().all()
        op.step("db.select", "Fetched node rows", nodes=len(rows))

        api_targets: set[str] = set()
        node_exporter_targets: set[str] = set()

        for node in rows:
            host = ""
            api_port = default_api_port
            if node.api_endpoint:
                endpoint_host, endpoint_port = _target_from_endpoint(node.api_endpoint, default_api_port)
                host = endpoint_host
                api_port = endpoint_port
            elif node.mesh_ip:
                host = node.mesh_ip

            host = _normalize_host(host)
            if not host:
                continue

            api_target = f"{host}:{api_port}"
            node_exporter_target = f"{host}:{node_exporter_port}"
            api_targets.add(api_target)
            node_exporter_targets.add(node_exporter_target)
            op.child(
                "target.build",
                f"node.{node.id}",
                "Prepared scrape targets",
                api_target=api_target,
                node_exporter_target=node_exporter_target,
            )

        if include_localhost_targets:
            api_targets.add(f"127.0.0.1:{default_api_port}")
            node_exporter_targets.add(f"127.0.0.1:{node_exporter_port}")
            op.step("target.local", "Included localhost monitoring targets")

        alertmanager_targets = _split_targets(alertmanager_targets_raw)
        if not alertmanager_targets:
            alertmanager_targets = ["127.0.0.1:9093"]
            op.step_warning(
                "alertmanager.default",
                "No Alertmanager targets configured; using localhost default",
            )

        api_target_list = _sorted_unique(api_targets)
        node_exporter_target_list = _sorted_unique(node_exporter_targets)
        alertmanager_target_list = sorted(set(alertmanager_targets))

        lines: list[str] = [
            "global:",
            f"  scrape_interval: {_seconds_interval(scrape_interval_seconds)}",
            f"  evaluation_interval: {_seconds_interval(evaluation_interval_seconds)}",
            "",
            "rule_files:",
            f"  - {rules_path}",
            "",
            "alerting:",
            "  alertmanagers:",
            "    - static_configs:",
            "        - targets:",
        ]
        for target in alertmanager_target_list:
            lines.append(f"            - {target}")

        lines.extend(
            [
                "",
                "scrape_configs:",
                "  - job_name: uptimemesh",
                f"    metrics_path: {app_metrics_path}",
                "    static_configs:",
                "      - targets:",
            ]
        )
        for target in api_target_list:
            lines.append(f"          - {target}")

        lines.extend(
            [
                "",
                "  - job_name: node_exporter",
                "    static_configs:",
                "      - targets:",
            ]
        )
        for target in node_exporter_target_list:
            lines.append(f"          - {target}")

        config = "\n".join(lines).rstrip() + "\n"
        op.step(
            "config.build",
            "Rendered Prometheus config",
            api_targets=len(api_target_list),
            node_exporter_targets=len(node_exporter_target_list),
            alertmanager_targets=len(alertmanager_target_list),
            lines=len(lines),
        )

        return PrometheusRenderResult(
            config=config,
            api_targets=api_target_list,
            node_exporter_targets=node_exporter_target_list,
            alertmanager_targets=alertmanager_target_list,
        )
