from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.endpoint import Endpoint
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.gateway import GatewayRouteEndpointOut, GatewayRouteOut
from app.services import applications as applications_service
from app.services import cluster_settings
from app.utils import sanitize_label

_logger = get_logger("services.gateway")


@dataclass(frozen=True)
class GatewayRenderResult:
    config: str
    routes: list[GatewayRouteOut]
    route_count: int
    upstream_count: int


def _sanitize_name(raw: str, fallback: str) -> str:
    value = sanitize_label(raw, max_len=63).replace("-", "_")
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        value = sanitize_label(fallback, max_len=63).replace("-", "_")
    return value or "item"


def _normalize_path(raw: str, fallback: str) -> str:
    value = raw.strip()
    if not value:
        value = fallback
    if not value.startswith("/"):
        value = "/" + value
    return re.sub(r"/{2,}", "/", value)


def _normalize_host(raw: str, fallback: str = "_") -> str:
    value = raw.strip().lower()
    return value or fallback


def _normalize_listen(raw: str) -> str:
    value = raw.strip()
    return value or "0.0.0.0:80"


def _resolve_gateway_route(
    *,
    service_id: str,
    service_name: str,
    service_spec: dict[str, object],
) -> tuple[bool, str, str]:
    gateway = service_spec.get("gateway")
    gateway_map = gateway if isinstance(gateway, dict) else {}
    enabled = bool(gateway_map.get("enabled", False))
    if not enabled:
        return False, "", ""

    host = _normalize_host(str(gateway_map.get("host", "_")))
    default_path = f"/{_sanitize_name(service_name, fallback=service_id)}/"
    path = _normalize_path(str(gateway_map.get("path", default_path)), fallback=default_path)
    return True, host, path


async def list_gateway_routes(
    session: AsyncSession,
) -> list[GatewayRouteOut]:
    async with _logger.operation(
        "gateway.routes.list",
        "Building gateway routes from healthy endpoints",
    ) as op:
        query = (
            select(
                Service.id.label("service_id"),
                Service.name.label("service_name"),
                Service.spec.label("service_spec"),
                Replica.id.label("replica_id"),
                Endpoint.address.label("address"),
                Endpoint.port.label("port"),
            )
            .join(Replica, Replica.service_id == Service.id)
            .join(Endpoint, Endpoint.replica_id == Replica.id)
            .where(Endpoint.healthy.is_(True))
            .order_by(Service.name.asc(), Endpoint.address.asc(), Endpoint.port.asc())
        )
        rows = (await session.execute(query)).all()
        op.step("db.select", "Fetched candidate gateway rows", rows=len(rows))
        settings_map = await cluster_settings.get_settings_map(session)
        applications = applications_service.parse_applications_from_settings(settings_map)
        app_ids = {str(item.get("id")) for item in applications}
        domain_routes = applications_service.parse_domain_routes_from_settings(
            settings_map,
            application_ids=app_ids,
        )
        domain_bindings = applications_service.build_domain_bindings(
            applications=applications,
            domain_routes=domain_routes,
        )

        grouped: dict[str, dict[str, object]] = {}
        collisions: set[tuple[str, str]] = set()
        seen_routes: set[tuple[str, str]] = set()
        service_endpoints: dict[str, set[tuple[str, int]]] = {}
        service_names: dict[str, str] = {}
        for row in rows:
            service_id = str(row.service_id)
            service_name = str(row.service_name)
            service_names[service_id] = service_name
            service_spec = row.service_spec if isinstance(row.service_spec, dict) else {}
            service_endpoints.setdefault(service_id, set()).add((str(row.address), int(row.port)))
            enabled, host, path = _resolve_gateway_route(
                service_id=service_id,
                service_name=service_name,
                service_spec=service_spec,
            )
            if not enabled:
                continue

            route_key = (host, path)
            if route_key in seen_routes and service_id not in grouped:
                collisions.add(route_key)
                continue
            seen_routes.add(route_key)

            payload = grouped.get(service_id)
            if payload is None:
                upstream = f"svc_{_sanitize_name(service_name, fallback=service_id)}_{service_id[:8]}"
                payload = {
                    "service_id": service_id,
                    "service_name": service_name,
                    "host": host,
                    "path": path,
                    "upstream": _sanitize_name(upstream, fallback=f"svc_{service_id[:8]}"),
                    "endpoints": set(),
                }
                grouped[service_id] = payload

            payload["endpoints"].add((str(row.address), int(row.port)))

        domain_route_count = 0
        domain_route_skipped = 0
        for binding in domain_bindings:
            if not bool(binding.get("route_enabled", False)):
                continue
            service_id = str(binding.get("application_target_service_id") or "").strip()
            if not service_id:
                domain_route_skipped += 1
                continue
            endpoints = service_endpoints.get(service_id, set())
            if not endpoints:
                domain_route_skipped += 1
                continue
            host = _normalize_host(str(binding.get("domain") or "_"), fallback="_")
            path = _normalize_path(str(binding.get("path") or "/"), fallback="/")
            route_key = (host, path)
            if route_key in seen_routes:
                collisions.add(route_key)
                domain_route_skipped += 1
                continue
            seen_routes.add(route_key)
            app_id = str(binding.get("application_id") or "app")
            service_name = service_names.get(service_id, service_id)
            upstream_seed = f"app_{_sanitize_name(app_id, fallback='app')}_{service_id[:8]}"
            grouped[f"{service_id}:{host}:{path}"] = {
                "service_id": service_id,
                "service_name": service_name,
                "host": host,
                "path": path,
                "upstream": _sanitize_name(upstream_seed, fallback=f"app_{service_id[:8]}"),
                "endpoints": set(endpoints),
            }
            domain_route_count += 1

        routes: list[GatewayRouteOut] = []
        for value in grouped.values():
            raw_endpoints = sorted(list(value["endpoints"]))
            endpoints = [
                GatewayRouteEndpointOut(address=address, port=port) for address, port in raw_endpoints
            ]
            routes.append(
                GatewayRouteOut(
                    service_id=str(value["service_id"]),
                    service_name=str(value["service_name"]),
                    host=str(value["host"]),
                    path=str(value["path"]),
                    upstream=str(value["upstream"]),
                    endpoint_count=len(endpoints),
                    endpoints=endpoints,
                )
            )

        routes.sort(key=lambda item: (item.host, -len(item.path), item.service_name))
        if collisions:
            op.step_warning(
                "route.collision",
                "Skipped duplicate host/path routes across services",
                collisions=len(collisions),
            )
        op.step(
            "route.domain_bindings",
            "Applied domain-to-application route bindings",
            configured=len(domain_bindings),
            applied=domain_route_count,
            skipped=domain_route_skipped,
        )
        op.step(
            "route.build",
            "Built gateway routes",
            routes=len(routes),
            upstreams=len(routes),
        )
        return routes


def render_nginx_config(
    *,
    routes: list[GatewayRouteOut],
    listen: str,
    default_server_name: str,
) -> str:
    listen_value = _normalize_listen(listen)
    server_name_fallback = _normalize_host(default_server_name, fallback="_")

    grouped: dict[str, list[GatewayRouteOut]] = defaultdict(list)
    for route in routes:
        grouped[_normalize_host(route.host, fallback=server_name_fallback)].append(route)

    lines = [
        "worker_processes auto;",
        "pid /tmp/uptimemesh-nginx.pid;",
        "events {",
        "    worker_connections 1024;",
        "}",
        "http {",
        "    include       /etc/nginx/mime.types;",
        "    default_type  application/octet-stream;",
        "    sendfile on;",
        "    keepalive_timeout 65;",
        "    proxy_connect_timeout 5s;",
        "    proxy_read_timeout 30s;",
        "    proxy_send_timeout 30s;",
    ]

    for route in routes:
        lines.append(f"    upstream {route.upstream} {{")
        for endpoint in route.endpoints:
            lines.append(f"        server {endpoint.address}:{endpoint.port} max_fails=2 fail_timeout=3s;")
        lines.append("        keepalive 32;")
        lines.append("    }")

    if not grouped:
        lines.extend(
            [
                "    server {",
                f"        listen {listen_value};",
                f"        server_name {server_name_fallback};",
                "        return 503;",
                "    }",
            ]
        )
    else:
        for host, host_routes in sorted(grouped.items(), key=lambda item: item[0]):
            lines.extend(
                [
                    "    server {",
                    f"        listen {listen_value};",
                    f"        server_name {host};",
                ]
            )
            for route in sorted(host_routes, key=lambda item: (-len(item.path), item.path)):
                lines.extend(
                    [
                        f"        location {route.path} {{",
                        "            proxy_http_version 1.1;",
                        "            proxy_set_header Host $host;",
                        "            proxy_set_header X-Real-IP $remote_addr;",
                        "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                        "            proxy_set_header X-Forwarded-Proto $scheme;",
                        f"            proxy_pass http://{route.upstream};",
                        "        }",
                    ]
                )
            lines.append("    }")

    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


async def render_gateway_config(
    session: AsyncSession,
    *,
    listen: str,
    default_server_name: str,
) -> GatewayRenderResult:
    async with _logger.operation(
        "gateway.config.render",
        "Rendering NGINX gateway config",
        listen=listen,
        server_name=default_server_name,
    ) as op:
        routes = await list_gateway_routes(session)
        config = render_nginx_config(
            routes=routes,
            listen=listen,
            default_server_name=default_server_name,
        )
        op.step(
            "config.build",
            "Rendered NGINX gateway config",
            routes=len(routes),
            upstreams=len(routes),
            lines=len(config.splitlines()),
        )
        return GatewayRenderResult(
            config=config,
            routes=routes,
            route_count=len(routes),
            upstream_count=len(routes),
        )


def resolve_gateway_paths(
    *,
    config_path: str,
    candidate_path: str,
    backup_path: str,
) -> tuple[Path, Path, Path]:
    resolved: list[Path] = []
    for raw in (config_path, candidate_path, backup_path):
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        resolved.append(path)
    return resolved[0], resolved[1], resolved[2]
