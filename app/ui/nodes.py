from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.formatting import as_bool, as_utc, format_age, format_duration, format_remaining
from app.formatting import format_timestamp, format_value, parse_datetime, safe_float, safe_int
from app.services import cluster as cluster_service
from app.services import cluster_settings, discovery as discovery_service
from app.services import events as event_service
from app.services import nodes as node_service
from app.services import roles as role_service
from app.ui.events import event_field_summary


def build_node_summary(node: Any, now: datetime) -> dict[str, Any]:
    node_status = node.status or {}
    lease_expires = as_utc(node.lease_expires_at)
    heartbeat_at = as_utc(node.heartbeat_at)
    if lease_expires and lease_expires > now:
        health_key = "online"
    elif heartbeat_at and (now - heartbeat_at).total_seconds() <= 180:
        health_key = "stale"
    else:
        health_key = "offline"

    health_text = {"online": "Online", "stale": "Stale", "offline": "Offline"}.get(
        health_key, "Unknown"
    )
    health_tone = {"online": "success", "stale": "warning", "offline": "error"}.get(
        health_key, "neutral"
    )
    roles = [str(role) for role in (node.roles or [])]
    failover_state = str(node_status.get("wg_failover_state", "")).strip().lower()
    wg_failover = node_status.get("wg_failover_state") or "unknown"
    load_cpu = safe_float(node_status.get("load_cpu_score"), default=None)
    load_ram = safe_float(node_status.get("load_ram_score"), default=None)
    load_disk = safe_float(node_status.get("load_disk_score"), default=None)
    load_network = safe_float(node_status.get("load_network_score"), default=None)
    load_total = safe_float(node_status.get("load_total_score"), default=None)
    swim_state = str(node_status.get("swim_state", "unknown")).strip().lower() or "unknown"
    swim_incarnation = safe_int(str(node_status.get("swim_incarnation", "0")), default=0)
    schedulable = as_bool(node_status.get("schedulable"))
    if schedulable is None:
        schedulable = True
    draining = bool(as_bool(node_status.get("draining")) or False)
    identity_expires = as_utc(node.identity_expires_at)
    if identity_expires is None:
        identity_expiry_state = "unknown"
        identity_expiry_text = "Unknown"
        identity_expires_in = "-"
    else:
        seconds_until_expiry = int((identity_expires - now).total_seconds())
        identity_expires_in = format_remaining(now, identity_expires)
        if seconds_until_expiry <= 0:
            identity_expiry_state = "expired"
            identity_expiry_text = "Expired"
        elif seconds_until_expiry <= 3 * 24 * 3600:
            identity_expiry_state = "critical"
            identity_expiry_text = "Expiring Soon"
        elif seconds_until_expiry <= 14 * 24 * 3600:
            identity_expiry_state = "warning"
            identity_expiry_text = "Expiring"
        else:
            identity_expiry_state = "ok"
            identity_expiry_text = "Valid"

    if lease_expires and lease_expires > now:
        lease_state = f"Active ({format_remaining(now, lease_expires)})"
    elif lease_expires:
        lease_state = f"Expired ({format_age(now, lease_expires)})"
    else:
        lease_state = "No lease"

    return {
        "id": node.id,
        "name": node.name,
        "roles": roles,
        "roles_text": ", ".join(roles) if roles else "-",
        "mesh_ip": node.mesh_ip or "-",
        "endpoint": node.api_endpoint or "-",
        "lease_state": lease_state,
        "lease_expires_at": format_timestamp(lease_expires),
        "heartbeat_at": format_timestamp(heartbeat_at),
        "heartbeat_age": format_age(now, heartbeat_at),
        "health_key": health_key,
        "health_text": health_text,
        "health_tone": health_tone,
        "wg_active_route": node_status.get("wg_active_route") or "-",
        "wg_failover": wg_failover,
        "wg_failover_secondary": failover_state == "failover_secondary",
        "fingerprint": node.identity_fingerprint or "-",
        "identity_expires_at": format_timestamp(identity_expires),
        "identity_expires_in": identity_expires_in,
        "identity_expiry_state": identity_expiry_state,
        "identity_expiry_text": identity_expiry_text,
        "load_cpu": load_cpu,
        "load_ram": load_ram,
        "load_disk": load_disk,
        "load_network": load_network,
        "load_total": load_total,
        "swim_state": swim_state,
        "swim_incarnation": swim_incarnation,
        "schedulable": schedulable,
        "draining": draining,
        "maintenance_text": "Draining" if draining else "Schedulable" if schedulable else "Cordoned",
        "status": node_status,
    }


def extract_role_actuation_rows(node_status: dict[str, Any]) -> list[dict[str, Any]]:
    role_fields: dict[str, dict[str, Any]] = {}
    for key, value in node_status.items():
        if not isinstance(key, str) or not key.startswith("role."):
            continue
        parts = key.split(".")
        if len(parts) != 3:
            continue
        _, role_name, field_name = parts
        role_fields.setdefault(role_name, {})[field_name] = value

    rows: list[dict[str, Any]] = []
    for role_name in sorted(role_fields.keys()):
        fields = role_fields[role_name]
        apply_ok_raw = fields.get("apply_ok")
        if isinstance(apply_ok_raw, bool):
            apply_ok = apply_ok_raw
        elif isinstance(apply_ok_raw, str):
            apply_ok = apply_ok_raw.strip().lower() in {"1", "true", "yes"}
        else:
            apply_ok = None
        reload_exit_code_raw = fields.get("reload_exit_code")
        reload_exit_code = (
            safe_int(str(reload_exit_code_raw), default=0)
            if reload_exit_code_raw is not None and str(reload_exit_code_raw).strip() != ""
            else None
        )
        template_hash = str(fields.get("template_hash") or "").strip()
        error = str(fields.get("error") or "").strip()
        rows.append(
            {
                "role_name": role_name,
                "apply_ok": apply_ok,
                "apply_state": (
                    "healthy"
                    if apply_ok is True
                    else "error" if apply_ok is False and error else "unknown"
                ),
                "template_hash": template_hash or "-",
                "reload_exit_code": reload_exit_code,
                "error": error or "-",
            }
        )
    return rows


async def build_nodes_context(
    session: AsyncSession,
    *,
    settings: Settings,
    view_mode: str,
) -> dict[str, Any]:
    nodes = await node_service.list_nodes(session, limit=500)
    now = datetime.now(timezone.utc)
    node_rows = [build_node_summary(node, now) for node in nodes]
    online_count = sum(1 for row in node_rows if row["health_key"] == "online")
    stale_count = sum(1 for row in node_rows if row["health_key"] == "stale")
    offline_count = sum(1 for row in node_rows if row["health_key"] == "offline")
    failover_count = sum(1 for row in node_rows if row["wg_failover_secondary"])
    cert_expired = sum(1 for row in node_rows if row["identity_expiry_state"] == "expired")
    cert_critical = sum(1 for row in node_rows if row["identity_expiry_state"] == "critical")
    cert_warning = sum(1 for row in node_rows if row["identity_expiry_state"] == "warning")

    swim_members: dict[str, Any] = {}
    placement = await role_service.get_latest_placement(session)
    if view_mode == "map":
        swim_members = await cluster_service.list_swim_members(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    node_assignments = placement.get("node_assignments", {}) if isinstance(placement, dict) else {}

    links: list[dict[str, str]] = []
    node_map_rows: list[dict[str, Any]] = []
    if view_mode == "map":
        links_set: set[tuple[str, str]] = set()
        for source_node_id, swim_row in swim_members.items():
            peers = swim_row.get("peers") if isinstance(swim_row, dict) else {}
            if not isinstance(peers, dict):
                continue
            for peer_node_id in peers.keys():
                if not isinstance(peer_node_id, str) or peer_node_id == source_node_id:
                    continue
                source, target = sorted((source_node_id, peer_node_id))
                links_set.add((source, target))
        links = [{"source": source, "target": target} for source, target in sorted(links_set)]

        for row in node_rows:
            node_id = row["id"]
            swim_row = swim_members.get(node_id, {})
            if not isinstance(swim_row, dict):
                swim_row = {}
            placement_roles = node_assignments.get(node_id, []) if isinstance(node_assignments, dict) else []
            normalized_roles = [str(item) for item in placement_roles if isinstance(item, str)] or row["roles"]
            node_map_rows.append(
                {
                    "id": node_id,
                    "name": row["name"],
                    "health": row["health_key"],
                    "swim_state": str(swim_row.get("state") or row["swim_state"] or "unknown"),
                    "swim_incarnation": int(swim_row.get("incarnation") or row["swim_incarnation"] or 0),
                    "swim_updated_at": str(swim_row.get("updated_at") or ""),
                    "role_text": ", ".join(normalized_roles) if normalized_roles else "-",
                    "load_total": row["load_total"],
                    "load_cpu": row["load_cpu"],
                    "load_ram": row["load_ram"],
                    "load_disk": row["load_disk"],
                    "load_network": row["load_network"],
                }
            )

    role_rows = []
    if isinstance(placement_rows, list):
        for item in placement_rows:
            if not isinstance(item, dict):
                continue
            holders = item.get("holders", [])
            if not isinstance(holders, list):
                holders = []
            role_rows.append(
                {
                    "name": str(item.get("name") or ""),
                    "desired": int(item.get("desired") or 0),
                    "assigned": int(item.get("assigned") or 0),
                    "deficit": int(item.get("deficit") or 0),
                    "holders": holders,
                }
            )
    role_rows.sort(key=lambda row: row["name"])

    etcd_context = {
        "enabled": settings.etcd_enabled,
        "configured": bool(settings.etcd_endpoints.strip()),
        "summary_only": True,
        "member_count": 0,
        "healthy_endpoint_count": 0,
        "endpoint_count": 0,
        "quorum_required": 0,
        "has_quorum": False,
        "error": "",
    }
    if etcd_context["enabled"] and etcd_context["configured"]:
        settings_map = await cluster_settings.get_settings_map(session)
        etcd_status = settings_map.get("etcd_status", "unknown")
        etcd_context["has_quorum"] = etcd_status == "ok"
        etcd_context["healthy_endpoint_count"] = 1 if etcd_status == "ok" else 0
        etcd_context["endpoint_count"] = 1
        etcd_context["quorum_required"] = 1
        if etcd_status != "ok":
            etcd_context["error"] = f"Runtime etcd status: {etcd_status}"

    return {
        "view_mode": view_mode,
        "nodes": node_rows,
        "map_nodes": node_map_rows,
        "map_links": links,
        "role_rows": role_rows,
        "etcd": etcd_context,
        "node_total": len(node_rows),
        "node_online": online_count,
        "node_stale": stale_count,
        "node_offline": offline_count,
        "node_failover": failover_count,
        "cert_expired": cert_expired,
        "cert_critical": cert_critical,
        "cert_warning": cert_warning,
    }


async def build_node_detail_context(
    session: AsyncSession,
    *,
    settings: Settings,
    node: Any,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    node_row = build_node_summary(node, now)
    node_status = node.status or {}
    role_actuation_rows = extract_role_actuation_rows(node_status)
    swim_members = await cluster_service.list_swim_members(session)
    swim_member = swim_members.get(node.id, {})
    swim_peers = swim_member.get("peers") if isinstance(swim_member, dict) else {}
    if not isinstance(swim_peers, dict):
        swim_peers = {}
    swim_peer_rows = [
        {
            "node_id": peer_node_id,
            "state": str((peer_payload or {}).get("state") or "unknown"),
            "incarnation": int((peer_payload or {}).get("incarnation") or 0),
            "failures": int((peer_payload or {}).get("failures") or 0),
            "last_seen": str((peer_payload or {}).get("last_seen") or ""),
        }
        for peer_node_id, peer_payload in sorted(swim_peers.items())
        if isinstance(peer_node_id, str)
    ]
    placement = await role_service.get_latest_placement(session)
    placement_map = placement.get("placement_map", {}) if isinstance(placement, dict) else {}
    node_assignments = placement.get("node_assignments", {}) if isinstance(placement, dict) else {}
    placement_roles = node_assignments.get(node.id, []) if isinstance(node_assignments, dict) else []
    if not isinstance(placement_roles, list):
        placement_roles = []
    role_holder_rows = []
    if isinstance(placement_map, dict):
        for role_name, holders in sorted(placement_map.items()):
            if not isinstance(role_name, str) or not isinstance(holders, list):
                continue
            role_holder_rows.append(
                {
                    "role_name": role_name,
                    "is_holder": node.id in holders,
                    "holder_count": len(holders),
                }
            )
    known_status_keys = [
        ("enrolled_at", "Enrolled At"),
        ("node_role", "Role"),
        ("agent_runtime_enabled", "Agent Runtime"),
        ("agent_loop_at", "Agent Loop"),
        ("agent_version", "Agent Version"),
        ("wg_active_route", "WireGuard Active Route"),
        ("wg_failover_state", "WireGuard Failover"),
        ("wg_primary_health", "Primary Tunnel Healthy"),
        ("wg_secondary_health", "Secondary Tunnel Healthy"),
        ("wg_primary_router_reachable", "Primary Router Reachable"),
        ("wg_secondary_router_reachable", "Secondary Router Reachable"),
        ("wg_primary_tunnel", "Primary Tunnel"),
        ("wg_secondary_tunnel", "Secondary Tunnel"),
        ("wg_primary_peer_configured", "Primary Peer Configured"),
        ("wg_secondary_peer_configured", "Secondary Peer Configured"),
        ("wg_primary_peer_endpoint", "Primary Peer Endpoint"),
        ("wg_secondary_peer_endpoint", "Secondary Peer Endpoint"),
        ("wg_primary_public_key", "Primary Public Key"),
        ("wg_secondary_public_key", "Secondary Public Key"),
        ("public_key", "Node Public Key"),
        ("last_heartbeat_signed_at", "Last Signed Heartbeat"),
        ("schedulable", "Schedulable"),
        ("draining", "Draining"),
        ("load_cpu_score", "CPU Load"),
        ("load_ram_score", "RAM Load"),
        ("load_disk_score", "Disk Load"),
        ("load_network_score", "Network Load"),
        ("load_total_score", "Total Load"),
        ("swim_state", "SWIM State"),
        ("swim_incarnation", "SWIM Incarnation"),
        ("swim_peer_count", "SWIM Peer Count"),
    ]
    known_key_set = {key for key, _ in known_status_keys}
    known_status_rows = [
        {"key": key, "label": label, "value": format_value(node_status.get(key))}
        for key, label in known_status_keys
        if key in node_status
    ]
    extra_status_rows = [
        {"key": key, "label": key.replace("_", " ").title(), "value": format_value(node_status.get(key))}
        for key in sorted(node_status.keys())
        if key not in known_key_set and not str(key).startswith("role.")
    ]
    node_events = await event_service.list_events_for_node(session, node_id=node.id, limit=30)
    node_event_rows = []
    for event in node_events:
        event_fields = event.fields if isinstance(event.fields, dict) else {}
        node_event_rows.append(
            {
                "id": event.id,
                "name": event.name,
                "level": event.level,
                "category": event.category,
                "created_at": format_timestamp(as_utc(event.created_at)),
                "summary": event_field_summary(event_fields),
            }
        )
    node_event_warning_count = sum(
        1 for row in node_event_rows if row["level"] in {"WARNING", "ERROR", "CRITICAL"}
    )

    stale_after_seconds = max(settings.runtime_discovery_interval_seconds * 3, 90)
    endpoint_registry = await discovery_service.list_endpoint_registry(
        session,
        stale_after_seconds=stale_after_seconds,
        node_id=node.id,
    )
    node_endpoint_rows: list[dict[str, Any]] = []
    endpoint_state_counts = {"healthy": 0, "unhealthy": 0, "stale": 0}
    for endpoint in endpoint_registry:
        health_state = str(endpoint.get("health_state") or "unknown")
        if health_state in endpoint_state_counts:
            endpoint_state_counts[health_state] += 1
        age_seconds = endpoint.get("age_seconds")
        age_text = "-"
        if isinstance(age_seconds, int) and age_seconds >= 0:
            age_text = format_duration(age_seconds)
        node_endpoint_rows.append(
            {
                "service_name": str(endpoint.get("service_name") or ""),
                "service_id": str(endpoint.get("service_id") or ""),
                "replica_id": str(endpoint.get("replica_id") or ""),
                "address": str(endpoint.get("address") or ""),
                "port": endpoint.get("port"),
                "health_state": health_state,
                "last_checked_at": format_timestamp(parse_datetime(endpoint.get("last_checked_at"))),
                "age_text": age_text,
            }
        )
    node_endpoint_rows.sort(key=lambda row: (row["service_name"].lower(), row["replica_id"]))

    subsystem_rows: list[dict[str, str]] = []
    heartbeat_state = node_row["health_key"]
    subsystem_rows.append(
        {
            "name": "Node Reachability",
            "state_key": (
                "healthy"
                if heartbeat_state == "online"
                else "degraded" if heartbeat_state == "stale" else "error"
            ),
            "state_text": node_row["health_text"],
            "detail": f"heartbeat {node_row['heartbeat_age']} · {node_row['lease_state']}",
        }
    )

    loop_at = parse_datetime(node_status.get("agent_loop_at"))
    loop_age_seconds = int(max((now - loop_at).total_seconds(), 0)) if loop_at is not None else None
    loop_threshold = max(settings.runtime_heartbeat_interval_seconds * 3, 30)
    if loop_at is None:
        loop_state_key = "unknown"
        loop_state_text = "Unknown"
        loop_detail = "No loop timestamp reported."
    elif loop_age_seconds is not None and loop_age_seconds <= loop_threshold:
        loop_state_key = "healthy"
        loop_state_text = "Healthy"
        loop_detail = f"last loop {format_duration(loop_age_seconds)} ago"
    else:
        loop_state_key = "degraded"
        loop_state_text = "Lagging"
        loop_detail = (
            f"last loop {format_duration(loop_age_seconds or 0)} ago"
            if loop_age_seconds is not None
            else "Loop age unknown"
        )
    agent_runtime_row = {
        "name": "Agent Loop",
        "state_key": loop_state_key,
        "state_text": loop_state_text,
        "detail": loop_detail,
    }

    wg_primary = as_bool(node_status.get("wg_primary_health"))
    wg_secondary = as_bool(node_status.get("wg_secondary_health"))
    if wg_primary is None and wg_secondary is None:
        wg_state_key = "unknown"
        wg_state_text = "Unknown"
        wg_detail = "No tunnel health report yet."
    elif wg_primary or wg_secondary:
        if wg_primary and wg_secondary:
            wg_state_key = "healthy"
            wg_state_text = "Healthy"
        else:
            wg_state_key = "degraded"
            wg_state_text = "Degraded"
        wg_detail = f"primary={wg_primary} secondary={wg_secondary} route={node_row['wg_active_route']}"
    else:
        wg_state_key = "error"
        wg_state_text = "Down"
        wg_detail = f"primary={wg_primary} secondary={wg_secondary}"
    subsystem_rows.append(
        {
            "name": "Mesh Connectivity",
            "state_key": wg_state_key,
            "state_text": wg_state_text,
            "detail": wg_detail,
        }
    )

    swim_state_raw = str(swim_member.get("state") or node_row["swim_state"] or "unknown").strip().lower()
    if swim_state_raw in {"healthy", "alive"}:
        swim_state_key = "healthy"
    elif swim_state_raw in {"degraded", "suspect"}:
        swim_state_key = "degraded"
    elif swim_state_raw in {"dead", "offline"}:
        swim_state_key = "error"
    else:
        swim_state_key = "unknown"
    swim_row = {
        "name": "Peer Membership",
        "state_key": swim_state_key,
        "state_text": swim_state_raw or "unknown",
        "detail": f"incarnation {swim_member.get('incarnation', node_row['swim_incarnation'])} · peers {len(swim_peer_rows)}",
    }

    if role_actuation_rows:
        has_error = any(row["apply_state"] == "error" for row in role_actuation_rows)
        has_unknown = any(row["apply_state"] == "unknown" for row in role_actuation_rows)
        if has_error:
            role_state_key = "error"
            role_state_text = "Error"
        elif has_unknown:
            role_state_key = "degraded"
            role_state_text = "Partial"
        else:
            role_state_key = "healthy"
            role_state_text = "Healthy"
        role_detail = f"{len(role_actuation_rows)} runtime roles reported"
    else:
        role_state_key = "unknown"
        role_state_text = "Unknown"
        role_detail = "No runtime role actuation status yet."
    role_runtime_row = {
        "name": "Role Actuation",
        "state_key": role_state_key,
        "state_text": role_state_text,
        "detail": role_detail,
    }

    if not node_endpoint_rows:
        endpoint_state_key = "unknown"
        endpoint_state_text = "No Endpoints"
        endpoint_detail = "No endpoint checks reported on this node."
    elif endpoint_state_counts["unhealthy"] > 0:
        endpoint_state_key = "error"
        endpoint_state_text = "Unhealthy"
        endpoint_detail = (
            f"{endpoint_state_counts['unhealthy']} unhealthy · "
            f"{endpoint_state_counts['stale']} stale · {endpoint_state_counts['healthy']} healthy"
        )
    elif endpoint_state_counts["stale"] > 0:
        endpoint_state_key = "degraded"
        endpoint_state_text = "Stale"
        endpoint_detail = (
            f"{endpoint_state_counts['stale']} stale · {endpoint_state_counts['healthy']} healthy"
        )
    else:
        endpoint_state_key = "healthy"
        endpoint_state_text = "Healthy"
        endpoint_detail = f"{endpoint_state_counts['healthy']} healthy endpoints"
    subsystem_rows.append(
        {
            "name": "Service Endpoint Health",
            "state_key": endpoint_state_key,
            "state_text": endpoint_state_text,
            "detail": endpoint_detail,
        }
    )

    identity_state_key = {
        "ok": "healthy",
        "warning": "degraded",
        "critical": "error",
        "expired": "error",
    }.get(node_row["identity_expiry_state"], "unknown")
    identity_row = {
        "name": "Identity Certificate",
        "state_key": identity_state_key,
        "state_text": node_row["identity_expiry_text"],
        "detail": f"expires {node_row['identity_expires_in']} ({node_row['identity_expires_at']})",
    }
    subsystem_rows.extend([agent_runtime_row, swim_row, role_runtime_row, identity_row])

    return {
        "title": node_row["name"],
        "subtitle": "Node detail and runtime diagnostics",
        "node": node_row,
        "node_id": node.id,
        "node_labels": node.labels or {},
        "created_at": format_timestamp(node.created_at),
        "updated_at": format_timestamp(node.updated_at),
        "known_status_rows": known_status_rows,
        "extra_status_rows": extra_status_rows,
        "placement_roles": [str(item) for item in placement_roles if isinstance(item, str)],
        "role_holder_rows": role_holder_rows,
        "role_actuation_rows": role_actuation_rows,
        "swim_member": swim_member if isinstance(swim_member, dict) else {},
        "swim_peer_rows": swim_peer_rows,
        "subsystem_rows": subsystem_rows,
        "node_event_rows": node_event_rows,
        "node_event_warning_count": node_event_warning_count,
        "node_endpoint_rows": node_endpoint_rows,
        "endpoint_state_counts": endpoint_state_counts,
    }
