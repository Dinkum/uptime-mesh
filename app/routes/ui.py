from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.models.event import Event
from app.security import SESSION_COOKIE_NAME, create_session_token
from app.services import (
    auth as auth_service,
    cluster as cluster_service,
    cluster_settings,
    discovery as discovery_service,
    etcd as etcd_service,
    events as event_service,
    gateway as gateway_service,
    monitoring as monitoring_service,
    nodes as node_service,
    replicas as replica_service,
    roles as role_service,
    scheduler as scheduler_service,
    services as service_service,
    snapshots as snapshot_service,
    support_bundles as support_bundle_service,
)

router = APIRouter(prefix="/ui", include_in_schema=False)

templates = Jinja2Templates(directory="app/templates")
settings = get_settings()


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except Exception:  # noqa: BLE001
        return default


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def _base_context(request: Request, session: AsyncSession) -> Dict[str, Any]:
    settings_map = await cluster_settings.get_settings_map(session)
    path = request.url.path or "/ui"
    tab_prefixes = [
        ("/ui/nodes", "nodes"),
        ("/ui/network", "nodes"),
        ("/ui/roles", "nodes"),
        ("/ui/workloads", "workloads"),
        ("/ui/services", "workloads"),
        ("/ui/replicas", "workloads"),
        ("/ui/scheduler", "workloads"),
        ("/ui/infrastructure", "infrastructure"),
        ("/ui/wireguard", "infrastructure"),
        ("/ui/discovery", "infrastructure"),
        ("/ui/gateway", "infrastructure"),
        ("/ui/monitoring", "infrastructure"),
        ("/ui/events", "events"),
        ("/ui/settings", "settings"),
        ("/ui/support", "settings"),
    ]
    current_tab = "overview"
    if path == "/ui":
        current_tab = "overview"
    else:
        for prefix, tab_name in tab_prefixes:
            if path == prefix or path.startswith(f"{prefix}/"):
                current_tab = tab_name
                break

    return {
        "ui_prefix": "/ui",
        "current_tab": current_tab,
        "auth_user": getattr(request.state, "auth_user", ""),
        "etcd_status": settings_map.get("etcd_status", "unknown"),
        "etcd_last_sync_at": settings_map.get("etcd_last_sync_at"),
    }


def _format_timestamp(value: datetime | None) -> str:
    timestamp = _as_utc(value)
    if timestamp is None:
        return "-"
    return timestamp.strftime("%Y-%m-%d %H:%M:%SZ")


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, rem_seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s"
    hours, rem_minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {rem_minutes}m"
    days, rem_hours = divmod(hours, 24)
    return f"{days}d {rem_hours}h"


def _format_age(now: datetime, value: datetime | None) -> str:
    timestamp = _as_utc(value)
    if timestamp is None:
        return "-"
    seconds = max(int((now - timestamp).total_seconds()), 0)
    return f"{_format_duration(seconds)} ago"


def _format_remaining(now: datetime, value: datetime | None) -> str:
    timestamp = _as_utc(value)
    if timestamp is None:
        return "-"
    seconds = int((timestamp - now).total_seconds())
    if seconds <= 0:
        return "expired"
    return f"in {_format_duration(seconds)}"


def _format_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _build_node_summary(node: Any, now: datetime) -> dict[str, Any]:
    node_status = node.status or {}
    lease_expires = _as_utc(node.lease_expires_at)
    heartbeat_at = _as_utc(node.heartbeat_at)
    if lease_expires and lease_expires > now:
        health_key = "online"
    elif heartbeat_at and (now - heartbeat_at).total_seconds() <= 180:
        health_key = "stale"
    else:
        health_key = "offline"

    health_text = {"online": "Online", "stale": "Stale", "offline": "Offline"}.get(health_key, "Unknown")
    health_tone = {"online": "success", "stale": "warning", "offline": "error"}.get(health_key, "neutral")
    roles = [str(role) for role in (node.roles or [])]
    failover_state = str(node_status.get("wg_failover_state", "")).strip().lower()
    wg_failover = node_status.get("wg_failover_state") or "unknown"
    load_cpu = _safe_float(node_status.get("load_cpu_score"), default=None)
    load_ram = _safe_float(node_status.get("load_ram_score"), default=None)
    load_disk = _safe_float(node_status.get("load_disk_score"), default=None)
    load_network = _safe_float(node_status.get("load_network_score"), default=None)
    load_total = _safe_float(node_status.get("load_total_score"), default=None)
    swim_state = str(node_status.get("swim_state", "unknown")).strip().lower() or "unknown"
    swim_incarnation = _safe_int(str(node_status.get("swim_incarnation", "0")), default=0)
    identity_expires = _as_utc(node.identity_expires_at)
    if identity_expires is None:
        identity_expiry_state = "unknown"
        identity_expiry_text = "Unknown"
        identity_expires_in = "-"
    else:
        seconds_until_expiry = int((identity_expires - now).total_seconds())
        identity_expires_in = _format_remaining(now, identity_expires)
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
        lease_state = f"Active ({_format_remaining(now, lease_expires)})"
    elif lease_expires:
        lease_state = f"Expired ({_format_age(now, lease_expires)})"
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
        "lease_expires_at": _format_timestamp(lease_expires),
        "heartbeat_at": _format_timestamp(heartbeat_at),
        "heartbeat_age": _format_age(now, heartbeat_at),
        "health_key": health_key,
        "health_text": health_text,
        "health_tone": health_tone,
        "wg_active_route": node_status.get("wg_active_route") or "-",
        "wg_failover": wg_failover,
        "wg_failover_secondary": failover_state == "failover_secondary",
        "fingerprint": node.identity_fingerprint or "-",
        "identity_expires_at": _format_timestamp(identity_expires),
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
        "status": node_status,
    }


def _extract_role_actuation_rows(node_status: dict[str, Any]) -> list[dict[str, Any]]:
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
            _safe_int(str(reload_exit_code_raw), default=0)
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


@router.get("")
async def overview(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)

    nodes = await node_service.list_nodes(session)
    events = await event_service.list_events(session, limit=12)

    recent_event_count_q = await session.execute(
        select(func.count(Event.id)).where(Event.created_at >= window_start)
    )
    event_count_24h = int(recent_event_count_q.scalar_one() or 0)

    warning_event_count_q = await session.execute(
        select(func.count(Event.id)).where(
            Event.created_at >= window_start,
            Event.level.in_(["WARNING", "ERROR", "CRITICAL"]),
        )
    )
    warning_event_count_24h = int(warning_event_count_q.scalar_one() or 0)

    total_nodes = len(nodes)
    online_nodes = 0
    failover_nodes = 0
    newest_heartbeat: datetime | None = None
    observed_seconds = 0.0
    estimated_up_seconds = 0.0
    for node in nodes:
        lease_expires = _as_utc(node.lease_expires_at)
        heartbeat_at = _as_utc(node.heartbeat_at)
        created_at = _as_utc(node.created_at) or window_start
        status = node.status or {}

        if lease_expires and lease_expires > now:
            online_nodes += 1
        if str(status.get("wg_failover_state", "")).strip().lower() == "failover_secondary":
            failover_nodes += 1

        if heartbeat_at and (newest_heartbeat is None or heartbeat_at > newest_heartbeat):
            newest_heartbeat = heartbeat_at

        observed_start = max(created_at, window_start)
        node_observed_seconds = max((now - observed_start).total_seconds(), 0.0)
        if node_observed_seconds <= 0:
            continue
        observed_seconds += node_observed_seconds

        if lease_expires and lease_expires > now:
            estimated_up_seconds += node_observed_seconds
        elif heartbeat_at:
            bounded_hb = min(max(heartbeat_at, observed_start), now)
            estimated_up_seconds += max((bounded_hb - observed_start).total_seconds(), 0.0)

    uptime_pct_24h = (
        round((estimated_up_seconds / observed_seconds) * 100.0, 2) if observed_seconds > 0 else None
    )
    heartbeat_lag_seconds = (
        int(max((now - newest_heartbeat).total_seconds(), 0)) if newest_heartbeat is not None else None
    )
    healthy_node_pct = round((online_nodes / total_nodes) * 100.0, 1) if total_nodes > 0 else 0.0
    version_label = f"v{settings.app_version}"
    agent_version_label = f"v{settings.app_agent_version}" if settings.app_agent_version else "unknown"

    context = {
        "request": request,
        "title": "Overview",
        "subtitle": "",
        "node_count": total_nodes,
        "node_online_count": online_nodes,
        "node_offline_count": max(total_nodes - online_nodes, 0),
        "healthy_node_pct": healthy_node_pct,
        "uptime_pct_24h": uptime_pct_24h,
        "event_count_24h": event_count_24h,
        "warning_event_count_24h": warning_event_count_24h,
        "heartbeat_lag_seconds": heartbeat_lag_seconds,
        "failover_node_count": failover_nodes,
        "app_version": version_label,
        "agent_version": agent_version_label,
        "events": events,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("overview.html", context)


@router.get("/network")
async def network_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    return RedirectResponse(url="/ui/nodes?view=map", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/nodes")
async def nodes_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    view_mode = (request.query_params.get("view") or "table").strip().lower()
    if view_mode not in {"table", "map"}:
        view_mode = "table"

    nodes = await node_service.list_nodes(session, limit=500)
    now = datetime.now(timezone.utc)
    node_rows = [_build_node_summary(node, now) for node in nodes]
    online_count = sum(1 for row in node_rows if row["health_key"] == "online")
    stale_count = sum(1 for row in node_rows if row["health_key"] == "stale")
    offline_count = sum(1 for row in node_rows if row["health_key"] == "offline")
    failover_count = sum(1 for row in node_rows if row["wg_failover_secondary"])
    cert_expired = sum(1 for row in node_rows if row["identity_expiry_state"] == "expired")
    cert_critical = sum(1 for row in node_rows if row["identity_expiry_state"] == "critical")
    cert_warning = sum(1 for row in node_rows if row["identity_expiry_state"] == "warning")

    swim_members = await cluster_service.list_swim_members(session)
    placement = await role_service.get_latest_placement(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    node_assignments = placement.get("node_assignments", {}) if isinstance(placement, dict) else {}

    links_set: set[tuple[str, str]] = set()
    for source_node_id, swim_row in swim_members.items():
        peers = swim_row.get("peers") if isinstance(swim_row, dict) else {}
        if not isinstance(peers, dict):
            continue
        for peer_node_id in peers.keys():
            if not isinstance(peer_node_id, str) or peer_node_id == source_node_id:
                continue
            links_set.add(tuple(sorted((source_node_id, peer_node_id))))
    links = [{"source": source, "target": target} for source, target in sorted(links_set)]

    node_map_rows = []
    for row in node_rows:
        node_id = row["id"]
        swim_row = swim_members.get(node_id, {})
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
        "member_count": 0,
        "healthy_endpoint_count": 0,
        "endpoint_count": 0,
        "quorum_required": 0,
        "has_quorum": False,
        "error": "",
    }
    if etcd_context["enabled"] and etcd_context["configured"]:
        try:
            members = await etcd_service.member_list()
            endpoint_health = await etcd_service.endpoint_health()
            etcd_context["member_count"] = len(members)
            etcd_context["endpoint_count"] = len(endpoint_health)
            etcd_context["healthy_endpoint_count"] = sum(1 for item in endpoint_health if item.healthy)
            quorum_required = (max(etcd_context["member_count"], 1) // 2) + 1
            etcd_context["quorum_required"] = quorum_required
            etcd_context["has_quorum"] = etcd_context["healthy_endpoint_count"] >= quorum_required
        except Exception as exc:  # noqa: BLE001
            etcd_context["error"] = f"{type(exc).__name__}: {exc}"

    context = {
        "request": request,
        "title": "Nodes",
        "subtitle": "Inventory, topology, and role placement",
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
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("nodes.html", context)


@router.get("/nodes/{node_id}")
async def node_detail_page(
    node_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    node = await node_service.get_node(session, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    now = datetime.now(timezone.utc)
    node_row = _build_node_summary(node, now)
    node_status = node.status or {}
    role_actuation_rows = _extract_role_actuation_rows(node_status)
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
        {"key": key, "label": label, "value": _format_value(node_status.get(key))}
        for key, label in known_status_keys
        if key in node_status
    ]
    extra_status_rows = [
        {"key": key, "label": key.replace("_", " ").title(), "value": _format_value(node_status.get(key))}
        for key in sorted(node_status.keys())
        if key not in known_key_set and not str(key).startswith("role.")
    ]

    context = {
        "request": request,
        "title": node_row["name"],
        "subtitle": "Node detail and runtime diagnostics",
        "node": node_row,
        "node_id": node.id,
        "node_labels": node.labels or {},
        "created_at": _format_timestamp(node.created_at),
        "updated_at": _format_timestamp(node.updated_at),
        "known_status_rows": known_status_rows,
        "extra_status_rows": extra_status_rows,
        "placement_roles": [str(item) for item in placement_roles if isinstance(item, str)],
        "role_holder_rows": role_holder_rows,
        "role_actuation_rows": role_actuation_rows,
        "swim_member": swim_member if isinstance(swim_member, dict) else {},
        "swim_peer_rows": swim_peer_rows,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("node_detail.html", context)


@router.get("/roles")
async def roles_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    specs = await role_service.get_role_specs(session)
    placement = await role_service.get_latest_placement(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    by_role_name = {
        str(item.get("name")): item for item in placement_rows if isinstance(item, dict)
    }
    role_rows = []
    for role_name, spec in sorted(specs.items()):
        placement_row = by_role_name.get(role_name, {})
        holders = placement_row.get("holders", []) if isinstance(placement_row, dict) else []
        if not isinstance(holders, list):
            holders = []
        role_rows.append(
            {
                "name": role_name,
                "kind": spec.get("kind", "replicated"),
                "priority": spec.get("priority", 0),
                "ratio": spec.get("ratio", 0.0),
                "min_replicas": spec.get("min_replicas", 0),
                "max_replicas": spec.get("max_replicas", 0),
                "desired": placement_row.get("desired", 0),
                "assigned": placement_row.get("assigned", 0),
                "deficit": placement_row.get("deficit", 0),
                "holders": holders,
            }
        )
    context = {
        "request": request,
        "title": "Roles",
        "subtitle": "Role specs, deterministic placement, and current holders",
        "generated_at": placement.get("generated_at", "") if isinstance(placement, dict) else "",
        "warnings": placement.get("warnings", []) if isinstance(placement, dict) else [],
        "role_rows": role_rows,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("roles.html", context)


@router.get("/roles/{role_name}")
async def role_detail_page(
    role_name: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    specs = await role_service.get_role_specs(session)
    if role_name not in specs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    placement = await role_service.get_latest_placement(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    placement_map = placement.get("placement_map", {}) if isinstance(placement, dict) else {}
    role_row = next(
        (item for item in placement_rows if isinstance(item, dict) and item.get("name") == role_name),
        {},
    )
    holders = placement_map.get(role_name, []) if isinstance(placement_map, dict) else []
    if not isinstance(holders, list):
        holders = []

    nodes = await node_service.list_nodes(session, limit=500)
    now = datetime.now(timezone.utc)
    node_by_id = {node.id: _build_node_summary(node, now) for node in nodes}
    holder_nodes = [node_by_id[item] for item in holders if item in node_by_id]
    context = {
        "request": request,
        "title": f"Role · {role_name}",
        "subtitle": "Role specification, placement counts, and holder nodes",
        "role_name": role_name,
        "spec": specs[role_name],
        "placement": role_row if isinstance(role_row, dict) else {},
        "holder_nodes": holder_nodes,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("role_detail.html", context)


@router.get("/workloads")
async def workloads_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    subtab = (request.query_params.get("tab") or "services").strip().lower()
    if subtab not in {"services", "replicas", "scheduler"}:
        subtab = "services"

    services = await service_service.list_services(session, limit=2000)
    replicas = await replica_service.list_replicas(session, limit=2000)
    now = datetime.now(timezone.utc)
    rollout_rows = service_service.build_rollout_rows(services, replicas, now=now)
    stalled_rollouts = sum(1 for row in rollout_rows if row["state_key"] == "stalled")
    error_rollouts = sum(1 for row in rollout_rows if row["state_key"] == "error")
    service_name_by_id = {str(service.id): str(service.name) for service in services}
    service_generation_by_id = {
        str(service.id): int(getattr(service, "generation", 0) or 0) for service in services
    }
    replica_rows: list[dict[str, Any]] = []
    for replica in replicas:
        status = replica.status if isinstance(replica.status, dict) else {}
        service_id = str(replica.service_id)
        current_generation = service_generation_by_id.get(service_id, 0)
        applied_generation = _safe_int(str(status.get("applied_generation", "0")), default=0)
        update_state = str(status.get("update_state", "unknown")).strip().lower() or "unknown"
        replica_rows.append(
            {
                "id": replica.id,
                "service_id": service_id,
                "service_name": service_name_by_id.get(service_id, service_id),
                "node_id": replica.node_id,
                "desired_state": replica.desired_state,
                "update_state": update_state,
                "applied_generation": applied_generation,
                "target_generation": current_generation,
                "updated_at": _format_timestamp(_as_utc(getattr(replica, "updated_at", None))),
            }
        )
    replica_rows.sort(key=lambda row: (row["service_name"].lower(), row["id"]))
    plan = await scheduler_service.get_cached_plan(session)

    context = {
        "request": request,
        "title": "Workloads",
        "subtitle": "Services, replicas, and scheduler plan",
        "workloads_subtab": subtab,
        "services": services,
        "rollout_rows": rollout_rows,
        "stalled_rollouts": stalled_rollouts,
        "error_rollouts": error_rollouts,
        "replica_rows": replica_rows,
        "plan": plan,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("workloads.html", context)


@router.get("/services")
async def services_page() -> Any:
    return RedirectResponse(url="/ui/workloads?tab=services", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/replicas")
async def replicas_page() -> Any:
    return RedirectResponse(url="/ui/workloads?tab=replicas", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/scheduler")
async def scheduler_page() -> Any:
    return RedirectResponse(url="/ui/workloads?tab=scheduler", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/events")
async def events_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    events = await event_service.list_events(session, limit=50)
    context = {
        "request": request,
        "title": "Events",
        "subtitle": "Audit timeline and live stream",
        "events": events,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("events.html", context)


@router.get("/infrastructure")
async def infrastructure_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    subtab = (request.query_params.get("tab") or "wireguard").strip().lower()
    if subtab not in {"wireguard", "discovery", "gateway", "monitoring", "cdn"}:
        subtab = "wireguard"

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

    records = await discovery_service.list_discovery_services(
        session,
        domain=settings.runtime_discovery_domain,
    )
    stale_after_seconds = max(settings.runtime_discovery_interval_seconds * 3, 90)
    endpoint_registry = await discovery_service.list_endpoint_registry(
        session,
        stale_after_seconds=stale_after_seconds,
    )
    endpoint_rows: list[dict[str, Any]] = []
    for endpoint in endpoint_registry:
        age_seconds = endpoint.get("age_seconds")
        age_text = "-"
        if isinstance(age_seconds, int) and age_seconds >= 0:
            age_text = _format_duration(age_seconds)
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
                "last_checked_at": _format_timestamp(_as_utc(endpoint.get("last_checked_at"))),
                "age_text": age_text,
            }
        )
    healthy_total = sum(1 for item in endpoint_rows if item["health_state"] == "healthy")
    unhealthy_total = sum(1 for item in endpoint_rows if item["health_state"] == "unhealthy")
    stale_total = sum(1 for item in endpoint_rows if item["health_state"] == "stale")

    routes = await gateway_service.list_gateway_routes(session)
    healthcheck_urls = [
        item.strip()
        for item in settings.runtime_gateway_healthcheck_urls.split(",")
        if item.strip()
    ]

    paths = monitoring_service.resolve_monitoring_paths(
        config_path=settings.runtime_monitoring_prometheus_config_path,
        candidate_path=settings.runtime_monitoring_prometheus_candidate_path,
        backup_path=settings.runtime_monitoring_prometheus_backup_path,
    )

    def split_csv(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(",") if item.strip()]

    api_targets = split_csv(settings_map.get("monitoring_api_targets", ""))
    node_exporter_targets = split_csv(settings_map.get("monitoring_node_exporter_targets", ""))
    alertmanager_targets = split_csv(settings_map.get("monitoring_alertmanager_targets", ""))
    content = await cluster_service.get_active_content(session)
    cdn_seeded_at = settings_map.get("internal_cdn_seeded_at", "")

    context = {
        "request": request,
        "title": "Infrastructure",
        "subtitle": "WireGuard, discovery, gateway, monitoring, and content cache",
        "infra_subtab": subtab,
        "wireguard_rows": wireguard_rows,
        "records": records,
        "domain": settings.runtime_discovery_domain,
        "zone_endpoint": "/discovery/dns/zone",
        "corefile_endpoint": "/discovery/dns/corefile",
        "service_count": _safe_int(settings_map.get("discovery_service_count", "0")),
        "endpoint_count": _safe_int(settings_map.get("discovery_endpoint_count", "0")),
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
        "route_count": _safe_int(settings_map.get("gateway_route_count", "0"), default=len(routes)),
        "upstream_count": _safe_int(
            settings_map.get("gateway_upstream_count", "0"), default=len(routes)
        ),
        "gateway_last_sync_at": settings_map.get("gateway_last_sync_at", ""),
        "gateway_last_apply_status": settings_map.get("gateway_last_apply_status", "unknown"),
        "gateway_last_apply_error": settings_map.get("gateway_last_apply_error", ""),
        "healthcheck_urls": healthcheck_urls,
        "monitoring_enabled": settings.runtime_monitoring_enable,
        "monitoring_config_endpoint": "/monitoring/prometheus/config",
        "monitoring_config_path": str(paths.config_path),
        "monitoring_config_sha256": settings_map.get("monitoring_config_sha256", ""),
        "api_targets": api_targets,
        "node_exporter_targets": node_exporter_targets,
        "alertmanager_targets": alertmanager_targets,
        "api_target_count": _safe_int(
            settings_map.get("monitoring_api_target_count", "0"),
            default=len(api_targets),
        ),
        "node_exporter_target_count": _safe_int(
            settings_map.get("monitoring_node_exporter_target_count", "0"),
            default=len(node_exporter_targets),
        ),
        "alertmanager_target_count": _safe_int(
            settings_map.get("monitoring_alertmanager_target_count", "0"),
            default=len(alertmanager_targets),
        ),
        "monitoring_last_sync_at": settings_map.get("monitoring_last_sync_at", ""),
        "monitoring_last_apply_status": settings_map.get("monitoring_last_apply_status", "unknown"),
        "monitoring_last_apply_error": settings_map.get("monitoring_last_apply_error", ""),
        "cdn_version": str(content.get("version") or ""),
        "cdn_hash_sha256": str(content.get("hash_sha256") or ""),
        "cdn_size_bytes": _safe_int(content.get("size_bytes"), default=0),
        "cdn_seeded_at": cdn_seeded_at,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("infrastructure.html", context)


@router.get("/wireguard")
async def wireguard_page() -> Any:
    return RedirectResponse(url="/ui/infrastructure?tab=wireguard", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/discovery")
async def discovery_page() -> Any:
    return RedirectResponse(url="/ui/infrastructure?tab=discovery", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/gateway")
async def gateway_page() -> Any:
    return RedirectResponse(url="/ui/infrastructure?tab=gateway", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/monitoring")
async def monitoring_page() -> Any:
    return RedirectResponse(url="/ui/infrastructure?tab=monitoring", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/support")
async def support_page() -> Any:
    return RedirectResponse(url="/ui/settings?section=support", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/settings")
async def settings_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    password_updated = request.query_params.get("password_updated") == "1"
    repo_updated = request.query_params.get("repo_updated") == "1"
    active_section = (request.query_params.get("section") or "auth").strip().lower()
    if active_section not in {"auth", "support"}:
        active_section = "auth"
    settings_map = await cluster_settings.get_settings_map(session)
    snapshots = await snapshot_service.list_snapshots(session)
    bundles = await support_bundle_service.list_support_bundles(session)
    context = {
        "request": request,
        "title": "Settings",
        "subtitle": "Authentication, preferences, snapshots, and support bundles",
        "settings_section": active_section,
        "username": await auth_service.get_username(session),
        "password_success": "Password updated successfully." if password_updated else "",
        "password_error": "",
        "repo_success": "Repository URL updated successfully." if repo_updated else "",
        "repo_error": "",
        "github_repo_url": settings_map.get("github_repo_url", "https://github.com/Dinkum/uptime-mesh"),
        "snapshots": snapshots,
        "bundles": bundles,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("settings.html", context)


@router.post("/settings/password")
async def change_password(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
) -> Any:
    username = await auth_service.get_username(session)
    settings_map = await cluster_settings.get_settings_map(session)
    snapshots = await snapshot_service.list_snapshots(session)
    bundles = await support_bundle_service.list_support_bundles(session)
    error = ""
    success = ""
    status_code = status.HTTP_200_OK

    if not current_password or not new_password or not confirm_password:
        error = "All password fields are required."
        status_code = status.HTTP_400_BAD_REQUEST
    elif new_password != confirm_password:
        error = "New password and confirmation do not match."
        status_code = status.HTTP_400_BAD_REQUEST
    elif len(new_password) < 8:
        error = "New password must be at least 8 characters."
        status_code = status.HTTP_400_BAD_REQUEST
    else:
        auth_user = getattr(request.state, "auth_user", "")
        changed, message = await auth_service.change_password(
            session,
            username=auth_user,
            current_password=current_password,
            new_password=new_password,
        )
        if changed:
            success = "Password updated successfully."
            session_token = create_session_token(
                username=auth_user,
                secret_key=settings.auth_secret_key,
                ttl_seconds=settings.auth_session_ttl_seconds,
            )
            response = RedirectResponse(
                url="/ui/settings?password_updated=1", status_code=status.HTTP_303_SEE_OTHER
            )
            response.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=session_token,
                max_age=settings.auth_session_ttl_seconds,
                httponly=True,
                secure=settings.auth_cookie_secure,
                samesite="lax",
                path="/",
            )
            return response

        error = message or "Unable to update password."
        status_code = status.HTTP_400_BAD_REQUEST

    context = {
        "request": request,
        "title": "Settings",
        "subtitle": "Authentication, preferences, snapshots, and support bundles",
        "settings_section": "auth",
        "username": username,
        "password_success": success,
        "password_error": error,
        "repo_success": "",
        "repo_error": "",
        "github_repo_url": settings_map.get(
            "github_repo_url",
            "https://github.com/Dinkum/uptime-mesh",
        ),
        "snapshots": snapshots,
        "bundles": bundles,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("settings.html", context, status_code=status_code)


@router.post("/settings/repo")
async def update_repo_url(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    github_repo_url: str = Form(default=""),
) -> Any:
    clean_url = github_repo_url.strip()
    error = ""
    success = ""
    status_code = status.HTTP_200_OK
    if not clean_url:
        error = "Repository URL is required."
        status_code = status.HTTP_400_BAD_REQUEST
    elif not clean_url.startswith("https://github.com/"):
        error = "Repository URL must start with https://github.com/."
        status_code = status.HTTP_400_BAD_REQUEST
    else:
        await cluster_settings.set_setting(session, "github_repo_url", clean_url)
        success = "Repository URL updated successfully."
        response = RedirectResponse(url="/ui/settings?repo_updated=1", status_code=status.HTTP_303_SEE_OTHER)
        return response

    context = {
        "request": request,
        "title": "Settings",
        "subtitle": "Authentication, preferences, snapshots, and support bundles",
        "settings_section": "auth",
        "username": await auth_service.get_username(session),
        "password_success": "",
        "password_error": "",
        "repo_success": success,
        "repo_error": error,
        "github_repo_url": clean_url or "https://github.com/Dinkum/uptime-mesh",
        "snapshots": await snapshot_service.list_snapshots(session),
        "bundles": await support_bundle_service.list_support_bundles(session),
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("settings.html", context, status_code=status_code)
