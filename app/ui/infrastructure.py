from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.formatting import format_bytes, format_duration, format_timestamp
from app.formatting import format_value, parse_datetime, safe_int
from app.services import cluster as cluster_service
from app.services import cluster_settings, discovery as discovery_service
from app.services import etcd as etcd_service
from app.services import gateway as gateway_service
from app.services import nodes as node_service


def _split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


async def build_infrastructure_context(
    session: AsyncSession,
    *,
    settings: Settings,
    subtab: str,
) -> dict[str, Any]:
    settings_map = await cluster_settings.get_settings_map(session)
    nodes = await node_service.list_nodes(session, limit=500)
    wireguard_rows = []
    for node in nodes:
        status = node.status or {}
        wireguard_rows.append(
            {
                "node_id": node.id,
                "primary_tunnel": status.get("wg_primary_tunnel"),
                "secondary_tunnel": status.get("wg_secondary_tunnel"),
                "primary_router_reachable": status.get("wg_primary_router_reachable"),
                "secondary_router_reachable": status.get("wg_secondary_router_reachable"),
                "active_route": status.get("wg_active_route"),
                "failover_state": status.get("wg_failover_state"),
                "primary_peer_configured": status.get("wg_primary_peer_configured"),
                "secondary_peer_configured": status.get("wg_secondary_peer_configured"),
                "primary_peer_endpoint": status.get("wg_primary_peer_endpoint"),
                "secondary_peer_endpoint": status.get("wg_secondary_peer_endpoint"),
            }
        )
    swim_state_counts = {"healthy": 0, "degraded": 0, "dead": 0, "unknown": 0}
    swim_rows: list[dict[str, Any]] = []
    swim_peer_total = 0
    if subtab == "swim":
        swim_members = await cluster_service.list_swim_members(session)
        known_node_ids = {node.id for node in nodes}
        for node in nodes:
            member = swim_members.get(node.id, {})
            if not isinstance(member, dict):
                member = {}
            member_state = str(
                member.get("state")
                or (node.status or {}).get("swim_state")
                or "unknown"
            ).strip().lower()
            if member_state not in swim_state_counts:
                member_state = "unknown"
            swim_state_counts[member_state] += 1
            raw_member_peers = member.get("peers")
            member_peers = raw_member_peers if isinstance(raw_member_peers, dict) else {}
            suspect_count = 0
            dead_count = 0
            for peer_payload in member_peers.values():
                if not isinstance(peer_payload, dict):
                    continue
                peer_state = str(peer_payload.get("state") or "unknown").strip().lower()
                if peer_state in {"degraded", "suspect"}:
                    suspect_count += 1
                elif peer_state == "dead":
                    dead_count += 1
            raw_member_flags = member.get("flags")
            member_flags = raw_member_flags if isinstance(raw_member_flags, dict) else {}
            interesting_flags = []
            for key in sorted(member_flags.keys()):
                if len(interesting_flags) >= 4:
                    break
                interesting_flags.append(f"{key}={format_value(member_flags.get(key))}")
            swim_rows.append(
                {
                    "node_id": node.id,
                    "state": member_state,
                    "incarnation": safe_int(member.get("incarnation"), default=0),
                    "updated_at": str(member.get("updated_at") or ""),
                    "peer_count": len(member_peers),
                    "suspect_peers": suspect_count,
                    "dead_peers": dead_count,
                    "flags_preview": " | ".join(interesting_flags) if interesting_flags else "-",
                }
            )
        for node_id, member in swim_members.items():
            if node_id in known_node_ids or not isinstance(member, dict):
                continue
            member_state = str(member.get("state") or "unknown").strip().lower()
            if member_state not in swim_state_counts:
                member_state = "unknown"
            swim_state_counts[member_state] += 1
            raw_member_peers = member.get("peers")
            member_peers = raw_member_peers if isinstance(raw_member_peers, dict) else {}
            swim_rows.append(
                {
                    "node_id": node_id,
                    "state": member_state,
                    "incarnation": safe_int(member.get("incarnation"), default=0),
                    "updated_at": str(member.get("updated_at") or ""),
                    "peer_count": len(member_peers),
                    "suspect_peers": 0,
                    "dead_peers": 0,
                    "flags_preview": "-",
                }
            )
        swim_rows.sort(key=lambda row: row["node_id"])
        swim_peer_total = sum(int(row["peer_count"]) for row in swim_rows)

    records: list[Any] = []
    stale_after_seconds = max(settings.runtime_discovery_interval_seconds * 3, 90)
    endpoint_rows: list[dict[str, Any]] = []
    if subtab == "discovery":
        records = await discovery_service.list_discovery_services(
            session,
            domain=settings.runtime_discovery_domain,
        )
        endpoint_registry = await discovery_service.list_endpoint_registry(
            session,
            stale_after_seconds=stale_after_seconds,
        )
        for endpoint in endpoint_registry:
            age_seconds = endpoint.get("age_seconds")
            age_text = "-"
            if isinstance(age_seconds, int) and age_seconds >= 0:
                age_text = format_duration(age_seconds)
            endpoint_rows.append(
                {
                    "endpoint_id": endpoint.get("endpoint_id", ""),
                    "service_name": endpoint.get("service_name", ""),
                    "service_id": endpoint.get("service_id", ""),
                    "replica_id": endpoint.get("replica_id", ""),
                    "node_id": endpoint.get("node_id", ""),
                    "address": endpoint.get("address", ""),
                    "port": endpoint.get("port", ""),
                    "health_state": endpoint.get("health_state", "unknown"),
                    "last_checked_at": format_timestamp(parse_datetime(endpoint.get("last_checked_at"))),
                    "age_text": age_text,
                }
            )
    healthy_total = sum(1 for item in endpoint_rows if item["health_state"] == "healthy")
    unhealthy_total = sum(1 for item in endpoint_rows if item["health_state"] == "unhealthy")
    stale_total = sum(1 for item in endpoint_rows if item["health_state"] == "stale")

    routes: list[Any] = []
    if subtab == "gateway":
        routes = await gateway_service.list_gateway_routes(session)
    healthcheck_urls = []
    if subtab == "gateway":
        healthcheck_urls = [
            item.strip()
            for item in settings.runtime_gateway_healthcheck_urls.split(",")
            if item.strip()
        ]

    api_targets: list[str] = []
    node_exporter_targets: list[str] = []
    alertmanager_targets: list[str] = []
    if subtab == "monitoring":
        api_targets = _split_csv(settings_map.get("monitoring_api_targets", ""))
        node_exporter_targets = _split_csv(settings_map.get("monitoring_node_exporter_targets", ""))
        alertmanager_targets = _split_csv(settings_map.get("monitoring_alertmanager_targets", ""))
    content: dict[str, Any] = {}
    if subtab == "cdn":
        content = await cluster_service.get_active_content(session)
    cdn_seeded_at = settings_map.get("internal_cdn_seeded_at", "")
    etcd_context: dict[str, Any] = {
        "enabled": settings.etcd_enabled,
        "configured": bool(settings.etcd_endpoints.strip()),
        "error": "",
        "members": [],
        "member_count": 0,
        "endpoint_health_rows": [],
        "endpoint_status_rows": [],
        "endpoint_count": 0,
        "healthy_endpoint_count": 0,
        "quorum_required": 0,
        "has_quorum": False,
        "leader_endpoint_count": 0,
        "alarm_rows": [],
    }
    if subtab == "etcd" and etcd_context["enabled"] and etcd_context["configured"]:
        try:
            member_rows = await etcd_service.member_list()
            health_rows = await etcd_service.endpoint_health()
            status_rows = await etcd_service.endpoint_status(health_rows=health_rows)
            alarm_rows = await etcd_service.alarm_list()
            etcd_context["members"] = member_rows
            etcd_context["member_count"] = len(member_rows)
            etcd_context["endpoint_health_rows"] = health_rows
            status_by_endpoint = {
                str(item.endpoint): item for item in health_rows if isinstance(item.endpoint, str)
            }
            display_rows: list[dict[str, Any]] = []
            for item in status_rows:
                endpoint = str(item.get("endpoint") or "")
                health = status_by_endpoint.get(endpoint)
                db_size = safe_int(item.get("db_size"), default=0)
                display_rows.append(
                    {
                        **item,
                        "healthy": bool(health.healthy) if health else bool(item.get("healthy")),
                        "error": (health.error if health else str(item.get("error") or "")),
                        "took_seconds": (health.took_seconds if health else 0.0),
                        "db_size_text": format_bytes(db_size),
                        "revision_text": f"{safe_int(item.get('revision'), default=0):,}",
                        "raft_term_text": f"{safe_int(item.get('raft_term'), default=0):,}",
                        "raft_index_text": f"{safe_int(item.get('raft_index'), default=0):,}",
                    }
                )
            etcd_context["endpoint_status_rows"] = display_rows
            etcd_context["endpoint_count"] = len(health_rows)
            etcd_context["healthy_endpoint_count"] = sum(1 for item in health_rows if item.healthy)
            quorum_required = (max(etcd_context["member_count"], 1) // 2) + 1
            etcd_context["quorum_required"] = quorum_required
            etcd_context["has_quorum"] = etcd_context["healthy_endpoint_count"] >= quorum_required
            etcd_context["leader_endpoint_count"] = sum(
                1 for item in status_rows if bool(item.get("is_leader"))
            )
            etcd_context["alarm_rows"] = alarm_rows
        except Exception as exc:  # noqa: BLE001
            etcd_context["error"] = f"{type(exc).__name__}: {exc}"

    return {
        "infra_subtab": subtab,
        "wireguard_rows": wireguard_rows,
        "records": records,
        "domain": settings.runtime_discovery_domain,
        "zone_endpoint": "/discovery/dns/zone",
        "corefile_endpoint": "/discovery/dns/corefile",
        "service_count": safe_int(settings_map.get("discovery_service_count", "0")),
        "endpoint_count": safe_int(settings_map.get("discovery_endpoint_count", "0")),
        "last_sync_at": settings_map.get("discovery_last_sync_at", ""),
        "endpoint_rows": endpoint_rows,
        "endpoint_registry_total": len(endpoint_rows),
        "endpoint_registry_healthy": healthy_total,
        "endpoint_registry_unhealthy": unhealthy_total,
        "endpoint_registry_stale": stale_total,
        "endpoint_registry_stale_after_seconds": stale_after_seconds,
        "gateway_enabled": settings.runtime_gateway_enable,
        "config_endpoint": "/gateway/nginx/config",
        "routes": routes,
        "route_count": safe_int(settings_map.get("gateway_route_count", "0"), default=len(routes)),
        "upstream_count": safe_int(
            settings_map.get("gateway_upstream_count", "0"), default=len(routes)
        ),
        "gateway_last_sync_at": settings_map.get("gateway_last_sync_at", ""),
        "gateway_last_apply_status": settings_map.get("gateway_last_apply_status", "unknown"),
        "gateway_last_apply_error": settings_map.get("gateway_last_apply_error", ""),
        "healthcheck_urls": healthcheck_urls,
        "monitoring_enabled": settings.runtime_monitoring_enable,
        "monitoring_config_endpoint": "/monitoring/prometheus/config",
        "monitoring_config_path": settings.runtime_monitoring_prometheus_config_path,
        "monitoring_config_sha256": settings_map.get("monitoring_config_sha256", ""),
        "api_targets": api_targets,
        "node_exporter_targets": node_exporter_targets,
        "alertmanager_targets": alertmanager_targets,
        "api_target_count": safe_int(
            settings_map.get("monitoring_api_target_count", "0"),
            default=len(api_targets),
        ),
        "node_exporter_target_count": safe_int(
            settings_map.get("monitoring_node_exporter_target_count", "0"),
            default=len(node_exporter_targets),
        ),
        "alertmanager_target_count": safe_int(
            settings_map.get("monitoring_alertmanager_target_count", "0"),
            default=len(alertmanager_targets),
        ),
        "monitoring_last_sync_at": settings_map.get("monitoring_last_sync_at", ""),
        "monitoring_last_apply_status": settings_map.get("monitoring_last_apply_status", "unknown"),
        "monitoring_last_apply_error": settings_map.get("monitoring_last_apply_error", ""),
        "cdn_version": str(content.get("version") or ""),
        "cdn_hash_sha256": str(content.get("hash_sha256") or ""),
        "cdn_size_bytes": safe_int(content.get("size_bytes"), default=0),
        "cdn_seeded_at": cdn_seeded_at,
        "etcd_runtime": etcd_context,
        "swim_rows": swim_rows,
        "swim_peer_total": swim_peer_total,
        "swim_state_counts": swim_state_counts,
    }
