from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import DEFAULT_AUTH_SECRET_KEY, DEFAULT_CLUSTER_SIGNING_KEY, Settings
from app.models.node import Node
from app.services import cluster_settings, discovery, gateway, nodes


def _check(name: str, state: str, detail: str, fix: str = "") -> dict[str, str]:
    return {"name": name, "state": state, "detail": detail, "fix": fix}


def _state_counts(checks: list[dict[str, str]]) -> dict[str, int]:
    return {
        "passes": sum(1 for item in checks if item["state"] == "pass"),
        "warnings": sum(1 for item in checks if item["state"] == "warning"),
        "blockers": sum(1 for item in checks if item["state"] == "blocker"),
    }


def _count_label(count: int, singular: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"


def _node_online(node: Node, now: datetime) -> bool:
    if node.lease_expires_at:
        lease_expires = node.lease_expires_at
        if lease_expires.tzinfo is None:
            lease_expires = lease_expires.replace(tzinfo=timezone.utc)
        if lease_expires > now:
            return True
    if node.heartbeat_at:
        heartbeat_at = node.heartbeat_at
        if heartbeat_at.tzinfo is None:
            heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)
        return (now - heartbeat_at.astimezone(timezone.utc)).total_seconds() <= 180
    return False


async def build_preflight_report(session: AsyncSession, settings: Settings) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    try:
        await session.execute(text("SELECT 1"))
        checks.append(_check("Database", "pass", "DB session is writable enough for control-plane reads."))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("Database", "blocker", f"{type(exc).__name__}: {exc}", "Fix DATABASE_URL and migrations."))

    settings_map = await cluster_settings.get_settings_map(session)
    etcd_status = settings_map.get("etcd_status", "unknown")
    if etcd_status == "ok":
        checks.append(_check("etcd", "pass", "Last runtime probe reports ok."))
    elif settings.etcd_enabled:
        checks.append(_check("etcd", "blocker", f"Runtime status is {etcd_status}.", "Restore etcd health or disable writes."))
    else:
        checks.append(_check("etcd", "warning", "etcd integration is disabled."))

    if settings.auth_secret_key == DEFAULT_AUTH_SECRET_KEY:
        checks.append(_check("Auth Secret", "blocker", "AUTH_SECRET_KEY is still the placeholder.", "Set AUTH_SECRET_KEY."))
    else:
        checks.append(_check("Auth Secret", "pass", "AUTH_SECRET_KEY is configured."))

    if settings.cluster_signing_key == DEFAULT_CLUSTER_SIGNING_KEY:
        checks.append(_check("Cluster Signing", "blocker", "CLUSTER_SIGNING_KEY is still the placeholder.", "Set CLUSTER_SIGNING_KEY."))
    else:
        checks.append(_check("Cluster Signing", "pass", "Cluster signing key is configured."))

    try:
        rendered = await gateway.render_gateway_config(
            session,
            listen=settings.runtime_gateway_listen,
            default_server_name=settings.runtime_gateway_server_name,
        )
        checks.append(_check("Gateway Config", "pass", f"{rendered.route_count} routes compile for NGINX."))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("Gateway Config", "blocker", str(exc), "Fix the route field named in the error."))

    try:
        discovery.render_corefile(
            domain=settings.runtime_discovery_domain,
            zone_file_path=settings.runtime_discovery_zone_path,
            listen=settings.runtime_discovery_listen,
            forwarders=settings.runtime_discovery_forwarders,
        )
        checks.append(_check("CoreDNS Config", "pass", "CoreDNS settings compile."))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("CoreDNS Config", "blocker", str(exc), "Fix discovery listen/domain/forwarder settings."))

    all_nodes = await nodes.list_nodes(session, limit=1000)
    online = sum(1 for node in all_nodes if _node_online(node, datetime.now(timezone.utc)))
    if not all_nodes:
        checks.append(_check("Agents", "warning", "No nodes are registered.", "Add a node."))
    elif online == 0:
        checks.append(_check("Agents", "blocker", f"{len(all_nodes)} nodes registered, none online.", "Restore agent heartbeat."))
    else:
        checks.append(_check("Agents", "pass", f"{online}/{len(all_nodes)} nodes are online."))

    for label, raw_path in (
        ("Snapshot Directory", settings.etcd_snapshot_dir),
        ("Support Bundle Directory", settings.support_bundle_dir),
    ):
        path = Path(raw_path)
        parent = path if path.exists() else path.parent
        if parent.exists():
            checks.append(_check(label, "pass", f"{parent} exists."))
        else:
            checks.append(_check(label, "warning", f"{parent} does not exist yet.", f"Create {parent}."))

    counts = _state_counts(checks)
    if counts["blockers"]:
        headline = f"Not ready for public traffic. {_count_label(counts['blockers'], 'blocker')}."
        ready = False
    elif counts["warnings"]:
        headline = f"Serving with warnings. {_count_label(counts['warnings'], 'warning')}."
        ready = True
    else:
        headline = "Ready for public traffic."
        ready = True

    next_fix = ""
    for item in checks:
        if item["state"] in {"blocker", "warning"}:
            next_fix = item["fix"] or item["detail"]
            break

    return {
        "ready": ready,
        "headline": headline,
        "passes": counts["passes"],
        "warnings": counts["warnings"],
        "blockers": counts["blockers"],
        "next_fix": next_fix,
        "checks": checks,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
