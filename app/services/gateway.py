from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.endpoint import Endpoint
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.gateway import GatewayRouteEndpointOut, GatewayRouteOut, GatewaySourceMapEntryOut
from app.services import applications as applications_service
from app.services import cluster_settings
from app.utils import sanitize_label
from app.validation import (
    dns_name,
    nginx_listen,
    nginx_path,
    nginx_upstream_name,
    upstream_endpoint,
)

_logger = get_logger("services.gateway")


@dataclass(frozen=True)
class GatewayRenderResult:
    config: str
    routes: list[GatewayRouteOut]
    route_count: int
    upstream_count: int


@dataclass
class GatewayRouteDraft:
    service_id: str
    service_name: str
    host: str
    path: str
    upstream: str
    endpoints: set[tuple[str, int]] = field(default_factory=set)

    def to_route(self) -> GatewayRouteOut:
        endpoints = [
            GatewayRouteEndpointOut(address=address, port=port)
            for address, port in sorted(self.endpoints)
        ]
        return GatewayRouteOut(
            service_id=self.service_id,
            service_name=self.service_name,
            host=self.host,
            path=self.path,
            upstream=self.upstream,
            endpoint_count=len(endpoints),
            endpoints=endpoints,
        )


@dataclass
class GatewayRouteAccumulator:
    grouped: dict[str, GatewayRouteDraft] = field(default_factory=dict)
    collisions: set[tuple[str, str]] = field(default_factory=set)
    seen: set[tuple[str, str]] = field(default_factory=set)

    def add(
        self,
        group_key: str,
        *,
        service_id: str,
        service_name: str,
        host: str,
        path: str,
        upstream_seed: str,
        upstream_fallback: str,
        endpoints: set[tuple[str, int]],
        merge_existing: bool,
    ) -> bool:
        route_key = (host, path)
        draft = self.grouped.get(group_key)
        if route_key in self.seen and not (merge_existing and draft is not None):
            self.collisions.add(route_key)
            return False
        self.seen.add(route_key)
        if draft is None:
            draft = GatewayRouteDraft(
                service_id=service_id,
                service_name=service_name,
                host=host,
                path=path,
                upstream=_sanitize_name(upstream_seed, fallback=upstream_fallback),
            )
            self.grouped[group_key] = draft
        draft.endpoints.update(endpoints)
        return True

    def routes(self) -> list[GatewayRouteOut]:
        return [draft.to_route() for draft in self.grouped.values()]


def _sanitize_name(raw: str, fallback: str) -> str:
    value = sanitize_label(raw, max_len=63).replace("-", "_")
    value = re.sub(r"_+", "_", value).strip("_")
    if not value:
        value = sanitize_label(fallback, max_len=63).replace("-", "_")
    if value and value[0].isdigit():
        value = f"u_{value}"
    return nginx_upstream_name(value or "item")


def _normalize_path(raw: str, fallback: str) -> str:
    value = raw.strip()
    if not value:
        value = fallback
    return nginx_path(re.sub(r"/{2,}", "/", value))


def _normalize_host(raw: str, fallback: str = "_") -> str:
    value = raw.strip().lower()
    return dns_name(value or fallback, allow_wildcard=True)


def _normalize_listen(raw: str) -> str:
    return nginx_listen(raw.strip() or "0.0.0.0:80")


def _nginx_endpoint(address: str, endpoint_port: int) -> str:
    clean_address, clean_port = upstream_endpoint(address, endpoint_port)
    if ":" in clean_address and not clean_address.startswith("["):
        return f"[{clean_address}]:{clean_port}"
    return f"{clean_address}:{clean_port}"


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

        route_accumulator = GatewayRouteAccumulator()
        service_endpoints: dict[str, set[tuple[str, int]]] = {}
        service_names: dict[str, str] = {}
        for row in rows:
            service_id = str(row.service_id)
            service_name = str(row.service_name)
            service_names[service_id] = service_name
            service_spec = row.service_spec if isinstance(row.service_spec, dict) else {}
            try:
                endpoint = upstream_endpoint(str(row.address), row.port)
                enabled, host, path = _resolve_gateway_route(
                    service_id=service_id,
                    service_name=service_name,
                    service_spec=service_spec,
                )
            except ValueError as exc:
                op.step_warning(
                    "route.invalid",
                    "Skipped gateway row with invalid generated config input",
                    service_id=service_id,
                    error=str(exc),
                )
                continue
            service_endpoints.setdefault(service_id, set()).add(endpoint)
            if not enabled:
                continue

            upstream_seed = f"svc_{_sanitize_name(service_name, fallback=service_id)}_{service_id[:8]}"
            route_accumulator.add(
                service_id,
                service_id=service_id,
                service_name=service_name,
                host=host,
                path=path,
                upstream_seed=upstream_seed,
                upstream_fallback=f"svc_{service_id[:8]}",
                endpoints={endpoint},
                merge_existing=True,
            )

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
            try:
                host = _normalize_host(str(binding.get("domain") or "_"), fallback="_")
                path = _normalize_path(str(binding.get("path") or "/"), fallback="/")
            except ValueError as exc:
                domain_route_skipped += 1
                op.step_warning(
                    "route.domain_invalid",
                    "Skipped domain route with invalid generated config input",
                    route_id=str(binding.get("id") or ""),
                    error=str(exc),
                )
                continue
            app_id = str(binding.get("application_id") or "app")
            service_name = service_names.get(service_id, service_id)
            upstream_seed = f"app_{_sanitize_name(app_id, fallback='app')}_{service_id[:8]}"
            added = route_accumulator.add(
                f"{service_id}:{host}:{path}",
                service_id=service_id,
                service_name=service_name,
                host=host,
                path=path,
                upstream_seed=upstream_seed,
                upstream_fallback=f"app_{service_id[:8]}",
                endpoints=set(endpoints),
                merge_existing=False,
            )
            if not added:
                domain_route_skipped += 1
                continue
            domain_route_count += 1

        routes = route_accumulator.routes()
        routes.sort(key=lambda item: (item.host, -len(item.path), item.service_name))
        if route_accumulator.collisions:
            op.step_warning(
                "route.collision",
                "Skipped duplicate host/path routes across services",
                collisions=len(route_accumulator.collisions),
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


async def build_gateway_source_map(session: AsyncSession) -> list[GatewaySourceMapEntryOut]:
    routes = await list_gateway_routes(session)
    entries: list[GatewaySourceMapEntryOut] = []
    for route in routes:
        source_type = "service.gateway"
        source_id = route.service_id
        if route.host != "_":
            entries.append(
                GatewaySourceMapEntryOut(
                    directive="server_name",
                    value=route.host,
                    source_type=source_type,
                    source_id=source_id,
                    service_id=route.service_id,
                    field="gateway.host",
                )
            )
        entries.append(
            GatewaySourceMapEntryOut(
                directive="location",
                value=route.path,
                source_type=source_type,
                source_id=source_id,
                service_id=route.service_id,
                field="gateway.path",
            )
        )
        entries.append(
            GatewaySourceMapEntryOut(
                directive="upstream",
                value=route.upstream,
                source_type="compiled",
                source_id=route.service_id,
                service_id=route.service_id,
                field="service.name",
            )
        )
        for endpoint in route.endpoints:
            entries.append(
                GatewaySourceMapEntryOut(
                    directive="server",
                    value=_nginx_endpoint(endpoint.address, endpoint.port),
                    source_type="endpoint",
                    source_id=f"{endpoint.address}:{endpoint.port}",
                    service_id=route.service_id,
                    field="Endpoint.address:port",
                )
            )
    return entries


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
        nginx_upstream_name(route.upstream)
        nginx_path(route.path)
        for endpoint in route.endpoints:
            upstream_endpoint(endpoint.address, endpoint.port)
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
            target = _nginx_endpoint(endpoint.address, endpoint.port)
            lines.append(f"        server {target} max_fails=2 fail_timeout=3s;")
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
