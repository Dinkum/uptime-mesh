from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.services import cluster_settings
from app.utils import sanitize_label

_logger = get_logger("services.applications")

APPLICATIONS_KEY = "applications_json"
DOMAIN_ROUTES_KEY = "domain_routes_json"

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_DEFAULT_APP_ID = "hello-world"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in {"1", "true", "yes", "on"}:
            return True
        if raw in {"0", "false", "no", "off"}:
            return False
    return default


def _normalize_path(value: Any, default: str = "/") -> str:
    raw = str(value or "").strip()
    if not raw:
        raw = default
    if not raw.startswith("/"):
        raw = f"/{raw}"
    while "//" in raw:
        raw = raw.replace("//", "/")
    return raw


def _normalize_domain(value: Any) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    labels = raw.split(".")
    if len(labels) < 2:
        return ""
    for label in labels:
        if not label or not _DOMAIN_LABEL_RE.fullmatch(label):
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""
    return raw


def _parse_json_list(raw: str) -> list[dict[str, Any]]:
    value = str(raw or "").strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in parsed:
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _normalize_application(item: dict[str, Any]) -> dict[str, Any] | None:
    app_id = sanitize_label(str(item.get("id") or item.get("name") or ""), max_len=48)
    if not app_id:
        return None
    name = str(item.get("name") or app_id).strip() or app_id
    description = str(item.get("description") or "").strip()
    target_service_id = str(item.get("target_service_id") or "").strip()
    default_path = _normalize_path(item.get("default_path"), default="/")
    enabled = _to_bool(item.get("enabled"), default=True)
    created_at = str(item.get("created_at") or _now_iso())
    updated_at = str(item.get("updated_at") or created_at)
    return {
        "id": app_id,
        "name": name,
        "description": description,
        "target_service_id": target_service_id,
        "default_path": default_path,
        "enabled": enabled,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _default_application() -> dict[str, Any]:
    now = _now_iso()
    return {
        "id": _DEFAULT_APP_ID,
        "name": "Hello World",
        "description": "Default bundled hello-world application.",
        "target_service_id": "",
        "default_path": "/",
        "enabled": True,
        "created_at": now,
        "updated_at": now,
    }


def parse_applications_from_settings(settings_map: dict[str, str]) -> list[dict[str, Any]]:
    raw_rows = _parse_json_list(settings_map.get(APPLICATIONS_KEY, ""))
    dedupe: dict[str, dict[str, Any]] = {}
    for item in raw_rows:
        normalized = _normalize_application(item)
        if normalized is None:
            continue
        dedupe[normalized["id"]] = normalized
    if _DEFAULT_APP_ID not in dedupe:
        dedupe[_DEFAULT_APP_ID] = _default_application()
    rows = list(dedupe.values())
    rows.sort(key=lambda item: str(item.get("name") or item["id"]).lower())
    return rows


def parse_domain_routes_from_settings(
    settings_map: dict[str, str],
    *,
    application_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    raw_rows = _parse_json_list(settings_map.get(DOMAIN_ROUTES_KEY, ""))
    dedupe_keys: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for item in raw_rows:
        route_id = sanitize_label(str(item.get("id") or uuid4().hex[:10]), max_len=48) or uuid4().hex[:10]
        domain = _normalize_domain(item.get("domain"))
        app_id = sanitize_label(str(item.get("application_id") or ""), max_len=48)
        if not domain or not app_id:
            continue
        if application_ids is not None and app_id not in application_ids:
            continue
        path = _normalize_path(item.get("path"), default="/")
        dedupe_key = (domain, path)
        if dedupe_key in dedupe_keys:
            continue
        dedupe_keys.add(dedupe_key)
        created_at = str(item.get("created_at") or _now_iso())
        updated_at = str(item.get("updated_at") or created_at)
        rows.append(
            {
                "id": route_id,
                "domain": domain,
                "application_id": app_id,
                "path": path,
                "enabled": _to_bool(item.get("enabled"), default=True),
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
    rows.sort(key=lambda item: (item["domain"], item["path"], item["application_id"]))
    return rows


def build_domain_bindings(
    *,
    applications: list[dict[str, Any]],
    domain_routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    app_map = {str(item.get("id")): item for item in applications if isinstance(item, dict)}
    bindings: list[dict[str, Any]] = []
    for route in domain_routes:
        app_id = str(route.get("application_id") or "")
        app = app_map.get(app_id)
        target_service_id = str((app or {}).get("target_service_id") or "").strip()
        bindings.append(
            {
                **route,
                "application_name": str((app or {}).get("name") or app_id or "unknown"),
                "application_target_service_id": target_service_id,
                "application_enabled": bool((app or {}).get("enabled", False)),
                "route_enabled": bool(route.get("enabled", False)),
                "routing_ready": bool(app and target_service_id and route.get("enabled", False)),
            }
        )
    return bindings


async def ensure_catalog_defaults(session: AsyncSession) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    settings_map = await cluster_settings.get_settings_map(session)
    apps = parse_applications_from_settings(settings_map)
    app_ids = {str(item["id"]) for item in apps}
    routes = parse_domain_routes_from_settings(settings_map, application_ids=app_ids)
    updates: dict[str, str] = {}
    rendered_apps = json.dumps(apps, separators=(",", ":"), sort_keys=True)
    rendered_routes = json.dumps(routes, separators=(",", ":"), sort_keys=True)
    if settings_map.get(APPLICATIONS_KEY, "") != rendered_apps:
        updates[APPLICATIONS_KEY] = rendered_apps
    if settings_map.get(DOMAIN_ROUTES_KEY, "") != rendered_routes:
        updates[DOMAIN_ROUTES_KEY] = rendered_routes
    if updates:
        await cluster_settings.upsert_settings(session, updates, sync_file=False)
        _logger.info(
            "applications.defaults",
            "Applied default application/domain catalog values",
            updates=list(updates.keys()),
        )
    return apps, routes


async def upsert_application(
    session: AsyncSession,
    *,
    app_id: str,
    name: str,
    description: str,
    target_service_id: str,
    default_path: str,
    enabled: bool,
) -> tuple[bool, str]:
    settings_map = await cluster_settings.get_settings_map(session)
    apps = parse_applications_from_settings(settings_map)
    normalized_id = sanitize_label(app_id or name, max_len=48)
    if not normalized_id:
        return False, "Application id or name is required."
    now = _now_iso()
    normalized_row = {
        "id": normalized_id,
        "name": str(name or normalized_id).strip() or normalized_id,
        "description": str(description or "").strip(),
        "target_service_id": str(target_service_id or "").strip(),
        "default_path": _normalize_path(default_path, default="/"),
        "enabled": bool(enabled),
        "updated_at": now,
    }
    existing_created_at = now
    updated = False
    for index, app in enumerate(apps):
        if str(app.get("id")) != normalized_id:
            continue
        existing_created_at = str(app.get("created_at") or now)
        apps[index] = {**app, **normalized_row, "created_at": existing_created_at}
        updated = True
        break
    if not updated:
        apps.append({**normalized_row, "created_at": now})
    apps.sort(key=lambda item: str(item.get("name") or item.get("id")).lower())
    await cluster_settings.upsert_settings(
        session,
        {APPLICATIONS_KEY: json.dumps(apps, separators=(",", ":"), sort_keys=True)},
        sync_file=True,
    )
    return True, normalized_id


async def upsert_domain_route(
    session: AsyncSession,
    *,
    route_id: str,
    domain: str,
    application_id: str,
    path: str,
    enabled: bool,
) -> tuple[bool, str]:
    settings_map = await cluster_settings.get_settings_map(session)
    apps = parse_applications_from_settings(settings_map)
    app_ids = {str(item["id"]) for item in apps}
    normalized_domain = _normalize_domain(domain)
    normalized_app_id = sanitize_label(application_id, max_len=48)
    if not normalized_domain:
        return False, "Valid domain is required."
    if not normalized_app_id or normalized_app_id not in app_ids:
        return False, "Application is required."

    routes = parse_domain_routes_from_settings(settings_map, application_ids=app_ids)
    normalized_route_id = sanitize_label(route_id, max_len=48) or uuid4().hex[:10]
    normalized_path = _normalize_path(path, default="/")
    now = _now_iso()
    candidate = {
        "id": normalized_route_id,
        "domain": normalized_domain,
        "application_id": normalized_app_id,
        "path": normalized_path,
        "enabled": bool(enabled),
        "updated_at": now,
    }
    replaced = False
    created_at = now
    for index, route in enumerate(routes):
        same_route_id = str(route.get("id")) == normalized_route_id
        same_binding = (
            str(route.get("domain")) == normalized_domain
            and str(route.get("path")) == normalized_path
        )
        if not same_route_id and not same_binding:
            continue
        created_at = str(route.get("created_at") or now)
        routes[index] = {**route, **candidate, "created_at": created_at}
        replaced = True
        break
    if not replaced:
        routes.append({**candidate, "created_at": now})
    routes.sort(key=lambda item: (item["domain"], item["path"], item["application_id"]))
    await cluster_settings.upsert_settings(
        session,
        {DOMAIN_ROUTES_KEY: json.dumps(routes, separators=(",", ":"), sort_keys=True)},
        sync_file=True,
    )
    return True, normalized_route_id


async def delete_domain_route(
    session: AsyncSession,
    *,
    route_id: str,
) -> bool:
    settings_map = await cluster_settings.get_settings_map(session)
    apps = parse_applications_from_settings(settings_map)
    app_ids = {str(item["id"]) for item in apps}
    routes = parse_domain_routes_from_settings(settings_map, application_ids=app_ids)
    remaining = [item for item in routes if str(item.get("id")) != route_id]
    if len(remaining) == len(routes):
        return False
    await cluster_settings.upsert_settings(
        session,
        {DOMAIN_ROUTES_KEY: json.dumps(remaining, separators=(",", ":"), sort_keys=True)},
        sync_file=True,
    )
    return True
