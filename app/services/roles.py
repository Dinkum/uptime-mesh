from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.services import cluster_settings
from app.services import etcd as etcd_service
from app.services import nodes as node_service

_logger = get_logger("services.roles")
_settings = get_settings()

ROLE_SPECS_KEY = "role_specs_json"
ROLE_PLACEMENT_KEY = "role_placement_json"
SWIM_MEMBERSHIP_KEY = "swim_membership_json"

DEFAULT_ROLE_SPECS: dict[str, dict[str, object]] = {
    "backend_server": {
        "kind": "replicated",
        "enabled": True,
        "min_replicas": 1,
        "max_replicas": 0,
        "ratio": 0.5,
        "priority": 100,
        "strict_separation_with": ["reverse_proxy"],
        "cooldown_seconds": 30,
        "slot_count": 0,
        "runtime_template": "nginx_backend",
    },
    "reverse_proxy": {
        "kind": "replicated",
        "enabled": True,
        "min_replicas": 1,
        "max_replicas": 0,
        "ratio": 0.5,
        "priority": 80,
        "strict_separation_with": ["backend_server"],
        "cooldown_seconds": 30,
        "slot_count": 0,
        "runtime_template": "caddy_reverse_proxy",
    },
    "dns_server": {
        "kind": "replicated",
        "enabled": False,
        "min_replicas": 0,
        "max_replicas": 2,
        "ratio": 0.0,
        "priority": 70,
        "strict_separation_with": [],
        "cooldown_seconds": 30,
        "slot_count": 0,
        "runtime_template": "unbound_dns",
    },
}


@dataclass(frozen=True)
class RolePlanRow:
    name: str
    enabled: bool
    desired: int
    assigned: int
    deficit: int
    holders: list[str]
    priority: int
    ratio: float
    min_replicas: int
    max_replicas: int


def _json_map(raw: str) -> dict[str, object]:
    value = raw.strip()
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _to_int(raw: object, default: int = 0) -> int:
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _to_float(raw: object, default: float = 0.0) -> float:
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _to_bool(raw: object, default: bool = True) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
    return default


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_score(role_name: str, node_id: str) -> int:
    raw = f"{role_name}|{node_id}".encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def _is_etcd_enabled() -> bool:
    return bool(_settings.etcd_enabled and _settings.etcd_endpoints.strip())


def _normalize_role_spec(name: str, payload: dict[str, object]) -> dict[str, object]:
    kind = str(payload.get("kind") or "replicated").strip().lower()
    if kind not in {"replicated", "scalable"}:
        kind = "replicated"

    enabled = _to_bool(payload.get("enabled"), default=True)
    min_replicas = max(_to_int(payload.get("min_replicas"), 1), 0)
    max_replicas = max(_to_int(payload.get("max_replicas"), 0), 0)
    ratio = min(max(_to_float(payload.get("ratio"), 0.5), 0.0), 1.0)
    priority = min(max(_to_int(payload.get("priority"), 50), 0), 1000)
    cooldown_seconds = min(max(_to_int(payload.get("cooldown_seconds"), 30), 0), 3600)
    slot_count = max(_to_int(payload.get("slot_count"), 0), 0)
    runtime_template = str(payload.get("runtime_template") or "").strip()
    strict_raw = payload.get("strict_separation_with")
    strict_with: list[str] = []
    if isinstance(strict_raw, list):
        for item in strict_raw:
            role = str(item).strip()
            if role and role != name and role not in strict_with:
                strict_with.append(role)

    return {
        "kind": kind,
        "enabled": enabled,
        "min_replicas": min_replicas,
        "max_replicas": max_replicas,
        "ratio": ratio,
        "priority": priority,
        "strict_separation_with": strict_with,
        "cooldown_seconds": cooldown_seconds,
        "slot_count": slot_count,
        "runtime_template": runtime_template,
    }


def _clamp_desired(
    *,
    healthy_nodes: int,
    ratio: float,
    min_replicas: int,
    max_replicas: int,
) -> int:
    raw = int((healthy_nodes * ratio) + 0.999999) if healthy_nodes > 0 and ratio > 0 else 0
    desired = max(raw, min_replicas)
    if max_replicas > 0:
        desired = min(desired, max_replicas)
    return max(desired, 0)


def _conflicts(
    role_name: str,
    candidate_node: str,
    occupancy: dict[str, set[str]],
    role_specs: dict[str, dict[str, object]],
) -> bool:
    existing = occupancy.get(candidate_node, set())
    if not existing:
        return False

    current_spec = role_specs.get(role_name, {})
    role_strict = {
        str(item)
        for item in current_spec.get("strict_separation_with", [])
        if isinstance(item, str) and item.strip()
    }
    for assigned_role in existing:
        if assigned_role in role_strict:
            return True
        assigned_spec = role_specs.get(assigned_role, {})
        assigned_strict = {
            str(item)
            for item in assigned_spec.get("strict_separation_with", [])
            if isinstance(item, str) and item.strip()
        }
        if role_name in assigned_strict:
            return True
    return False


async def get_role_specs(session: AsyncSession) -> dict[str, dict[str, object]]:
    async with _logger.operation("role_specs.get", "Loading role specs") as op:
        settings_map = await cluster_settings.get_settings_map(session)
        existing = _json_map(settings_map.get(ROLE_SPECS_KEY, ""))
        merged: dict[str, dict[str, object]] = {}
        for name, default_payload in DEFAULT_ROLE_SPECS.items():
            payload = default_payload
            if isinstance(existing.get(name), dict):
                payload = {**default_payload, **existing.get(name, {})}
            merged[name] = _normalize_role_spec(name, payload)

        for name, value in existing.items():
            if name in merged or not isinstance(value, dict):
                continue
            merged[name] = _normalize_role_spec(name, value)

        rendered = json.dumps(merged, separators=(",", ":"), sort_keys=True)
        if settings_map.get(ROLE_SPECS_KEY, "") != rendered:
            await cluster_settings.upsert_settings(session, {ROLE_SPECS_KEY: rendered}, sync_file=False)
            op.step("db.upsert", "Persisted normalized role specs", roles=len(merged))
        else:
            op.step("db.upsert", "Role specs already normalized", roles=len(merged))
        return merged


async def set_role_spec(
    session: AsyncSession,
    *,
    name: str,
    payload: dict[str, object],
) -> dict[str, object]:
    role_name = name.strip()
    if not role_name:
        raise ValueError("role name cannot be empty")

    async with _logger.operation("role_specs.set", "Updating role spec", role=role_name) as op:
        specs = await get_role_specs(session)
        specs[role_name] = _normalize_role_spec(role_name, payload)
        rendered = json.dumps(specs, separators=(",", ":"), sort_keys=True)
        await cluster_settings.upsert_settings(session, {ROLE_SPECS_KEY: rendered}, sync_file=False)
        op.step("db.commit", "Persisted role spec update")

        if _is_etcd_enabled():
            try:
                await etcd_service.put_value(
                    key=f"roles/specs/{role_name}",
                    value=json.dumps(specs[role_name], separators=(",", ":"), sort_keys=True),
                )
                op.step("etcd.upsert", "Upserted role spec to etcd")
            except Exception as exc:  # noqa: BLE001
                op.step_warning(
                    "etcd.upsert",
                    "Failed to upsert role spec to etcd",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
        return specs[role_name]


def _parse_swim_states(settings_map: dict[str, str]) -> dict[str, str]:
    raw = _json_map(settings_map.get(SWIM_MEMBERSHIP_KEY, ""))
    states: dict[str, str] = {}
    for node_id, value in raw.items():
        if not isinstance(node_id, str) or not isinstance(value, dict):
            continue
        states[node_id] = str(value.get("state") or "unknown").strip().lower()
    return states


def _previous_placement(settings_map: dict[str, str]) -> tuple[dict[str, list[str]], str]:
    raw = _json_map(settings_map.get(ROLE_PLACEMENT_KEY, ""))
    generated_at = str(raw.get("generated_at") or "") if isinstance(raw, dict) else ""
    placement_map: dict[str, list[str]] = {}
    roles_raw = raw.get("placement_map", {}) if isinstance(raw, dict) else {}
    if isinstance(roles_raw, dict):
        for role_name, holders in roles_raw.items():
            if not isinstance(role_name, str) or not isinstance(holders, list):
                continue
            placement_map[role_name] = [
                str(item) for item in holders if isinstance(item, str) and str(item).strip()
            ]
    return placement_map, generated_at


def _serialize_placement(
    *,
    generated_at: str,
    healthy_nodes: list[str],
    swim_states: dict[str, str],
    rows: list[RolePlanRow],
    warnings: list[str],
) -> dict[str, object]:
    placement_map = {row.name: list(row.holders) for row in rows}
    node_assignments: dict[str, list[str]] = {}
    for row in rows:
        for node_id in row.holders:
            node_assignments.setdefault(node_id, []).append(row.name)
    for node_id in node_assignments:
        node_assignments[node_id].sort()
    return {
        "generated_at": generated_at,
        "healthy_nodes": healthy_nodes,
        "swim_states": swim_states,
        "roles": [
            {
                "name": row.name,
                "enabled": row.enabled,
                "desired": row.desired,
                "assigned": row.assigned,
                "deficit": row.deficit,
                "holders": row.holders,
                "priority": row.priority,
                "ratio": row.ratio,
                "min_replicas": row.min_replicas,
                "max_replicas": row.max_replicas,
            }
            for row in rows
        ],
        "warnings": warnings,
        "placement_map": placement_map,
        "node_assignments": node_assignments,
    }


async def reconcile_placement(
    session: AsyncSession,
    *,
    persist: bool = True,
) -> dict[str, object]:
    async with _logger.operation("role_placement.reconcile", "Reconciling deterministic role placement", persist=persist) as op:
        specs = await get_role_specs(session)
        settings_map = await cluster_settings.get_settings_map(session)
        swim_states = _parse_swim_states(settings_map)
        nodes = await node_service.list_nodes(session, limit=1000)
        node_ids = [node.id for node in nodes]
        healthy_nodes = sorted(
            node_id
            for node_id in node_ids
            if swim_states.get(node_id, "unknown") == "healthy"
        )
        if not healthy_nodes:
            # Fallback to lease-recency when SWIM has not converged yet.
            now = datetime.now(timezone.utc)
            healthy_nodes = sorted(
                node.id for node in nodes if node.lease_expires_at is not None and node.lease_expires_at >= now
            )

        previous_map, previous_generated_at = _previous_placement(settings_map)
        role_order = sorted(
            specs.items(),
            key=lambda item: (-_to_int(item[1].get("priority"), 0), item[0]),
        )
        occupancy: dict[str, set[str]] = {}
        rows: list[RolePlanRow] = []
        warnings: list[str] = []

        for role_name, spec in role_order:
            enabled = _to_bool(spec.get("enabled"), default=True)
            ratio = _to_float(spec.get("ratio"), 0.5)
            min_replicas = max(_to_int(spec.get("min_replicas"), 1), 0)
            max_replicas = max(_to_int(spec.get("max_replicas"), 0), 0)
            desired = 0
            if enabled:
                if role_name == "dns_server":
                    # Stock DNS role is either disabled (0) or a resilient pair (2).
                    desired = 2 if len(healthy_nodes) >= 2 else 0
                    if len(healthy_nodes) < 2:
                        warnings.append("role dns_server enabled but requires at least 2 healthy nodes")
                else:
                    desired = _clamp_desired(
                        healthy_nodes=len(healthy_nodes),
                        ratio=ratio,
                        min_replicas=min_replicas,
                        max_replicas=max_replicas,
                    )

            incumbents = [item for item in previous_map.get(role_name, []) if item in healthy_nodes]
            holders: list[str] = []
            for node_id in incumbents:
                if len(holders) >= desired:
                    break
                if _conflicts(role_name, node_id, occupancy, specs):
                    continue
                holders.append(node_id)
                occupancy.setdefault(node_id, set()).add(role_name)

            ranked_nodes = sorted(
                healthy_nodes,
                key=lambda node_id: _hash_score(role_name, node_id),
                reverse=True,
            )
            for node_id in ranked_nodes:
                if len(holders) >= desired:
                    break
                if node_id in holders:
                    continue
                if _conflicts(role_name, node_id, occupancy, specs):
                    continue
                holders.append(node_id)
                occupancy.setdefault(node_id, set()).add(role_name)

            deficit = max(desired - len(holders), 0)
            if deficit:
                warnings.append(f"role {role_name} under target by {deficit} replica(s)")

            row = RolePlanRow(
                name=role_name,
                enabled=enabled,
                desired=desired,
                assigned=len(holders),
                deficit=deficit,
                holders=holders,
                priority=_to_int(spec.get("priority"), 0),
                ratio=ratio,
                min_replicas=min_replicas,
                max_replicas=max_replicas,
            )
            rows.append(row)
            op.child(
                "role.assign",
                role_name,
                "Assigned role holders",
                enabled=enabled,
                desired=desired,
                assigned=len(holders),
                deficit=deficit,
            )

        generated_at = _now_iso()
        payload = _serialize_placement(
            generated_at=generated_at,
            healthy_nodes=healthy_nodes,
            swim_states=swim_states,
            rows=rows,
            warnings=warnings,
        )
        payload["source"] = "runtime"
        payload["persisted"] = False
        payload["previous_generated_at"] = previous_generated_at or None

        if persist:
            rendered = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            await cluster_settings.upsert_settings(session, {ROLE_PLACEMENT_KEY: rendered}, sync_file=False)
            payload["persisted"] = True
            op.step("db.commit", "Persisted role placement state")

            if _is_etcd_enabled():
                try:
                    await etcd_service.put_value(
                        key="roles/placement/current",
                        value=rendered,
                    )
                    op.step("etcd.upsert", "Persisted role placement to etcd")
                except Exception as exc:  # noqa: BLE001
                    op.step_warning(
                        "etcd.upsert",
                        "Failed to persist role placement to etcd",
                        error_type=type(exc).__name__,
                        error=str(exc),
                    )
        return payload


async def get_latest_placement(session: AsyncSession) -> dict[str, object]:
    settings_map = await cluster_settings.get_settings_map(session)
    current = _json_map(settings_map.get(ROLE_PLACEMENT_KEY, ""))
    if current:
        return current
    return await reconcile_placement(session, persist=True)
