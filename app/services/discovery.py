from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.endpoint import Endpoint
from app.models.replica import Replica
from app.models.service import Service
from app.schemas.discovery import DiscoveryEndpointOut, DiscoveryServiceOut
from app.utils import sanitize_label

_logger = get_logger("services.discovery")


def sanitize_dns_label(raw: str, fallback: str = "item") -> str:
    value = sanitize_label(raw, max_len=63)
    if not value:
        value = sanitize_label(fallback, max_len=63)
    return value or "item"


def _normalize_domain(domain: str) -> str:
    value = domain.strip().lower().rstrip(".")
    if not value:
        return "mesh.local"
    return value


def _normalize_forwarders(raw: str) -> list[str]:
    forwarders: list[str] = []
    for item in raw.split():
        value = item.strip()
        if value:
            forwarders.append(value)
    if not forwarders:
        return ["/etc/resolv.conf"]
    return forwarders


async def list_discovery_services(
    session: AsyncSession,
    *,
    domain: str,
) -> list[DiscoveryServiceOut]:
    dns_domain = _normalize_domain(domain)
    async with _logger.operation(
        "discovery.services.list",
        "Building discovery records from healthy endpoints",
        domain=dns_domain,
    ) as op:
        query = (
            select(
                Service.id.label("service_id"),
                Service.name.label("service_name"),
                Replica.id.label("replica_id"),
                Endpoint.id.label("endpoint_id"),
                Endpoint.address.label("address"),
                Endpoint.port.label("port"),
            )
            .join(Replica, Replica.service_id == Service.id)
            .join(Endpoint, Endpoint.replica_id == Replica.id)
            .where(Endpoint.healthy.is_(True))
            .order_by(Service.name.asc(), Endpoint.id.asc())
        )
        rows = (await session.execute(query)).all()
        op.step("db.select", "Fetched healthy endpoint rows", rows=len(rows))
        grouped: dict[str, dict[str, object]] = {}
        for row in rows:
            service_id = str(row.service_id)
            service_name = str(row.service_name)
            service_label = sanitize_dns_label(service_name, fallback=f"svc-{service_id[:8]}")
            service_host = f"{service_label}.svc"
            service_fqdn = f"{service_host}.{dns_domain}."
            endpoint_label = sanitize_dns_label(str(row.endpoint_id), fallback="ep")
            endpoint_host = f"{endpoint_label}.{service_host}"
            endpoint_fqdn = f"{endpoint_host}.{dns_domain}."
            endpoint = DiscoveryEndpointOut(
                endpoint_id=str(row.endpoint_id),
                replica_id=str(row.replica_id),
                address=str(row.address),
                port=int(row.port),
                host=endpoint_host,
                host_fqdn=endpoint_fqdn,
            )

            payload = grouped.get(service_id)
            if payload is None:
                payload = {
                    "service_id": service_id,
                    "service_name": service_name,
                    "service": service_host,
                    "service_fqdn": service_fqdn,
                    "endpoints": [],
                }
                grouped[service_id] = payload
            payload["endpoints"].append(endpoint)

        results = [
            DiscoveryServiceOut(
                service_id=str(value["service_id"]),
                service_name=str(value["service_name"]),
                service=str(value["service"]),
                service_fqdn=str(value["service_fqdn"]),
                endpoints=list(value["endpoints"]),
            )
            for value in grouped.values()
        ]
        op.step(
            "records.build",
            "Built discovery records",
            services=len(results),
            endpoints=sum(len(item.endpoints) for item in results),
        )
        return results


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def list_endpoint_registry(
    session: AsyncSession,
    *,
    stale_after_seconds: int = 90,
) -> list[dict[str, object]]:
    threshold = max(30, stale_after_seconds)
    now = datetime.now(timezone.utc)
    async with _logger.operation(
        "discovery.endpoints.list",
        "Listing endpoint registry (all health states)",
        stale_after_seconds=threshold,
    ) as op:
        query = (
            select(
                Endpoint.id.label("endpoint_id"),
                Endpoint.replica_id.label("replica_id"),
                Endpoint.address.label("address"),
                Endpoint.port.label("port"),
                Endpoint.healthy.label("healthy"),
                Endpoint.last_checked_at.label("last_checked_at"),
                Endpoint.created_at.label("created_at"),
                Endpoint.updated_at.label("updated_at"),
                Replica.node_id.label("node_id"),
                Service.id.label("service_id"),
                Service.name.label("service_name"),
            )
            .join(Replica, Replica.id == Endpoint.replica_id)
            .join(Service, Service.id == Replica.service_id)
            .order_by(Service.name.asc(), Endpoint.id.asc())
        )
        rows = (await session.execute(query)).all()
        op.step("db.select", "Fetched endpoint rows", rows=len(rows))

        payload: list[dict[str, object]] = []
        for row in rows:
            last_checked_at = _as_utc(row.last_checked_at)
            updated_at = _as_utc(row.updated_at)
            created_at = _as_utc(row.created_at)
            observed_at = last_checked_at or updated_at or created_at
            age_seconds = int(max((now - observed_at).total_seconds(), 0)) if observed_at else None

            if observed_at and age_seconds is not None and age_seconds > threshold:
                health_state = "stale"
            elif bool(row.healthy):
                health_state = "healthy"
            else:
                health_state = "unhealthy"

            payload.append(
                {
                    "endpoint_id": str(row.endpoint_id),
                    "service_id": str(row.service_id),
                    "service_name": str(row.service_name),
                    "replica_id": str(row.replica_id),
                    "node_id": str(row.node_id),
                    "address": str(row.address),
                    "port": int(row.port),
                    "healthy": bool(row.healthy),
                    "health_state": health_state,
                    "last_checked_at": last_checked_at,
                    "age_seconds": age_seconds,
                }
            )

        op.step(
            "records.build",
            "Built endpoint registry payload",
            endpoints=len(payload),
            healthy=sum(1 for item in payload if item["health_state"] == "healthy"),
            unhealthy=sum(1 for item in payload if item["health_state"] == "unhealthy"),
            stale=sum(1 for item in payload if item["health_state"] == "stale"),
        )
        return payload


async def render_zone_file(
    session: AsyncSession,
    *,
    domain: str,
    ttl_seconds: int = 30,
) -> tuple[str, int, int]:
    dns_domain = _normalize_domain(domain)
    async with _logger.operation(
        "discovery.zone.render",
        "Rendering CoreDNS zone",
        domain=dns_domain,
        ttl_seconds=ttl_seconds,
    ) as op:
        services = await list_discovery_services(session, domain=dns_domain)
        serial = int(datetime.now(timezone.utc).strftime("%Y%m%d%H"))
        ns_host = f"ns1.{dns_domain}."
        lines = [
            f"$ORIGIN {dns_domain}.",
            f"$TTL {ttl_seconds}",
            (
                f"@ IN SOA {ns_host} hostmaster.{dns_domain}. "
                f"{serial} 60 30 120 30"
            ),
            f"@ IN NS {ns_host}",
            "ns1 IN A 127.0.0.1",
        ]

        endpoint_count = 0
        for service in services:
            service_addresses: dict[str, int] = defaultdict(int)
            for endpoint in service.endpoints:
                endpoint_count += 1
                service_addresses[endpoint.address] += 1
                lines.append(f"{endpoint.host} IN A {endpoint.address}")
                lines.append(
                    f"_tcp.{service.service} IN SRV 10 10 {endpoint.port} {endpoint.host_fqdn}"
                )
            for address in service_addresses:
                lines.append(f"{service.service} IN A {address}")

        zone = "\n".join(lines).rstrip() + "\n"
        op.step(
            "zone.complete",
            "Rendered zone data",
            services=len(services),
            endpoints=endpoint_count,
            lines=len(lines),
        )
        return zone, len(services), endpoint_count


def render_corefile(
    *,
    domain: str,
    zone_file_path: str,
    listen: str,
    forwarders: str,
) -> str:
    dns_domain = _normalize_domain(domain)
    listen_addr = listen.strip() or ".:53"
    zone_path = Path(zone_file_path).expanduser()
    if not zone_path.is_absolute():
        zone_path = (Path.cwd() / zone_path).resolve()
    forward_targets = " ".join(_normalize_forwarders(forwarders))

    return (
        f"{listen_addr} {{\n"
        "    errors\n"
        "    log\n"
        "    health\n"
        "    ready\n"
        f"    file {zone_path} {dns_domain}\n"
        "    reload 5s\n"
        "    cache 30\n"
        f"    forward . {forward_targets}\n"
        "}\n"
    )
