from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.security import SESSION_COOKIE_NAME, create_session_token
from app.services import (
    auth as auth_service,
    cluster_settings,
    discovery as discovery_service,
    events as event_service,
    gateway as gateway_service,
    monitoring as monitoring_service,
    nodes as node_service,
    replicas as replica_service,
    router_assignments as router_assignment_service,
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


async def _base_context(request: Request, session: AsyncSession) -> Dict[str, Any]:
    settings_map = await cluster_settings.get_settings_map(session)
    return {
        "ui_prefix": "/ui",
        "auth_user": getattr(request.state, "auth_user", ""),
        "etcd_status": settings_map.get("etcd_status", "unknown"),
        "etcd_last_sync_at": settings_map.get("etcd_last_sync_at"),
    }


@router.get("")
async def overview(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    nodes = await node_service.list_nodes(session)
    services = await service_service.list_services(session)
    replicas = await replica_service.list_replicas(session)
    router_assignments = await router_assignment_service.list_router_assignments(session)
    events = await event_service.list_events(session, limit=8)
    snapshots = await snapshot_service.list_snapshots(session, limit=1)
    bundles = await support_bundle_service.list_support_bundles(session, limit=1)

    context = {
        "request": request,
        "title": "Overview",
        "subtitle": "Live mesh health and cluster truth",
        "node_count": len(nodes),
        "service_count": len(services),
        "replica_count": len(replicas),
        "router_assignment_count": len(router_assignments),
        "router_assignments": router_assignments[:6],
        "events": events,
        "latest_snapshot": snapshots[0] if snapshots else None,
        "latest_bundle": bundles[0] if bundles else None,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("overview.html", context)


@router.get("/nodes")
async def nodes_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    nodes = await node_service.list_nodes(session)
    context = {
        "request": request,
        "title": "Nodes",
        "subtitle": "Roles, mesh IPs, and heartbeat status",
        "nodes": nodes,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("nodes.html", context)


@router.get("/services")
async def services_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    services = await service_service.list_services(session)
    context = {
        "request": request,
        "title": "Services",
        "subtitle": "Desired state and pinned placement",
        "services": services,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("services.html", context)


@router.get("/replicas")
async def replicas_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    replicas = await replica_service.list_replicas(session)
    context = {
        "request": request,
        "title": "Replicas",
        "subtitle": "Sandbox instances and health gates",
        "replicas": replicas,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("replicas.html", context)


@router.get("/scheduler")
async def scheduler_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    plan = await scheduler_service.reconcile_all_services(session, dry_run=True)
    context = {
        "request": request,
        "title": "Scheduler",
        "subtitle": "Policy-driven placement, reschedule, and rolling update planning",
        "plan": plan,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("scheduler.html", context)


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


@router.get("/wireguard")
async def wireguard_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
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

    context = {
        "request": request,
        "title": "WireGuard",
        "subtitle": "Dual tunnel state and active route preference",
        "wireguard_rows": wireguard_rows,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("wireguard.html", context)


@router.get("/discovery")
async def discovery_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    settings_map = await cluster_settings.get_settings_map(session)
    records = await discovery_service.list_discovery_services(
        session,
        domain=settings.runtime_discovery_domain,
    )
    context = {
        "request": request,
        "title": "Discovery",
        "subtitle": "CoreDNS records from healthy endpoint registry",
        "records": records,
        "domain": settings.runtime_discovery_domain,
        "zone_endpoint": "/discovery/dns/zone",
        "corefile_endpoint": "/discovery/dns/corefile",
        "service_count": _safe_int(settings_map.get("discovery_service_count", "0")),
        "endpoint_count": _safe_int(settings_map.get("discovery_endpoint_count", "0")),
        "last_sync_at": settings_map.get("discovery_last_sync_at", ""),
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("discovery.html", context)


@router.get("/gateway")
async def gateway_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    settings_map = await cluster_settings.get_settings_map(session)
    routes = await gateway_service.list_gateway_routes(session)
    healthcheck_urls = [
        item.strip()
        for item in settings.runtime_gateway_healthcheck_urls.split(",")
        if item.strip()
    ]
    context = {
        "request": request,
        "title": "Gateway",
        "subtitle": "NGINX ingress routes with safe reload pipeline",
        "enabled": settings.runtime_gateway_enable,
        "config_endpoint": "/gateway/nginx/config",
        "routes": routes,
        "route_count": _safe_int(settings_map.get("gateway_route_count", "0"), default=len(routes)),
        "upstream_count": _safe_int(
            settings_map.get("gateway_upstream_count", "0"), default=len(routes)
        ),
        "last_sync_at": settings_map.get("gateway_last_sync_at", ""),
        "last_apply_status": settings_map.get("gateway_last_apply_status", "unknown"),
        "last_apply_error": settings_map.get("gateway_last_apply_error", ""),
        "healthcheck_urls": healthcheck_urls,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("gateway.html", context)


@router.get("/monitoring")
async def monitoring_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    settings_map = await cluster_settings.get_settings_map(session)
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
    context = {
        "request": request,
        "title": "Monitoring",
        "subtitle": "Prometheus targets, alerting paths, and sync status",
        "enabled": settings.runtime_monitoring_enable,
        "config_endpoint": "/monitoring/prometheus/config",
        "config_path": str(paths.config_path),
        "config_sha256": settings_map.get("monitoring_config_sha256", ""),
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
        "last_sync_at": settings_map.get("monitoring_last_sync_at", ""),
        "last_apply_status": settings_map.get("monitoring_last_apply_status", "unknown"),
        "last_apply_error": settings_map.get("monitoring_last_apply_error", ""),
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("monitoring.html", context)


@router.get("/support")
async def support_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    snapshots = await snapshot_service.list_snapshots(session)
    bundles = await support_bundle_service.list_support_bundles(session)
    context = {
        "request": request,
        "title": "Support",
        "subtitle": "Snapshots, bundles, and break-glass tooling",
        "snapshots": snapshots,
        "bundles": bundles,
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("support.html", context)


@router.get("/settings")
async def settings_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    password_updated = request.query_params.get("password_updated") == "1"
    repo_updated = request.query_params.get("repo_updated") == "1"
    settings_map = await cluster_settings.get_settings_map(session)
    context = {
        "request": request,
        "title": "Settings",
        "subtitle": "Authentication and cluster preferences",
        "login_id": await auth_service.get_login_id(session),
        "password_success": "Password updated successfully." if password_updated else "",
        "password_error": "",
        "repo_success": "Repository URL updated successfully." if repo_updated else "",
        "repo_error": "",
        "github_repo_url": settings_map.get("github_repo_url", "https://github.com/Dinkum/uptime-mesh"),
    }
    context.update(
        {
            "ui_prefix": "/ui",
            "auth_user": getattr(request.state, "auth_user", ""),
            "etcd_status": settings_map.get("etcd_status", "unknown"),
            "etcd_last_sync_at": settings_map.get("etcd_last_sync_at"),
        }
    )
    return templates.TemplateResponse("settings.html", context)


@router.post("/settings/password")
async def change_password(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
) -> Any:
    login_id = await auth_service.get_login_id(session)
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
        "subtitle": "Authentication and cluster preferences",
        "login_id": login_id,
        "password_success": success,
        "password_error": error,
        "repo_success": "",
        "repo_error": "",
        "github_repo_url": (await cluster_settings.get_settings_map(session)).get(
            "github_repo_url",
            "https://github.com/Dinkum/uptime-mesh",
        ),
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
        "subtitle": "Authentication and cluster preferences",
        "login_id": await auth_service.get_login_id(session),
        "password_success": "",
        "password_error": "",
        "repo_success": success,
        "repo_error": error,
        "github_repo_url": clean_url or "https://github.com/Dinkum/uptime-mesh",
    }
    context.update(await _base_context(request, session))
    return templates.TemplateResponse("settings.html", context, status_code=status_code)
