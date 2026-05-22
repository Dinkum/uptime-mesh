from __future__ import annotations

import shlex
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session, get_writable_db_session
from app.formatting import as_utc as _as_utc
from app.formatting import form_bool as _as_form_bool
from app.formatting import format_timestamp as _format_timestamp
from app.formatting import parse_datetime as _parse_datetime
from app.models.event import Event
from app.security import SESSION_COOKIE_NAME, create_session_token
from app.security import create_csrf_token, verify_csrf_token
from app.services import (
    applications as applications_service,
    auth as auth_service,
    cluster as cluster_service,
    cluster_settings,
    events as event_service,
    nodes as node_service,
    preflight as preflight_service,
    roles as role_service,
)
from app.templates import render_template
from app.ui.events import build_events_context
from app.ui.infrastructure import build_infrastructure_context
from app.ui.nodes import build_node_detail_context, build_node_summary, build_nodes_context
from app.ui.settings import build_settings_context
from app.ui.workloads import build_workloads_context

router = APIRouter(prefix="/ui", include_in_schema=False)

settings = get_settings()


def _install_script_url(repo_url: str) -> str:
    clean = repo_url.strip().removesuffix(".git")
    if clean.startswith("https://github.com/"):
        slug = clean.removeprefix("https://github.com/").strip("/")
        if slug.count("/") >= 1:
            owner, repo, *_ = slug.split("/")
            return f"https://raw.githubusercontent.com/{owner}/{repo}/main/install.sh"
    return "https://raw.githubusercontent.com/Dinkum/uptime-mesh/main/install.sh"


def _install_join_command(peer: str, role: str, join_port: int, repo_url: str) -> str:
    install_url = _install_script_url(repo_url)
    command = (
        f"curl -fsSL {shlex.quote(install_url)} | "
        f"sudo UPTIMEMESH_REPO_URL={shlex.quote(repo_url)} bash -s -- --join {shlex.quote(peer)}"
    )
    if role and role != "auto":
        command = f"{command} --role {role}"
    if join_port != 8010:
        command = f"{command} --join-port {join_port}"
    return command


async def _not_found_response(
    request: Request,
    session: AsyncSession,
    *,
    title: str,
    message: str,
    back_url: str,
    back_label: str,
) -> Any:
    context = {
        "request": request,
        "title": title,
        "subtitle": "",
        "message": message,
        "back_url": back_url,
        "back_label": back_label,
    }
    context.update(await _base_context(request, session))
    return render_template(
        request,
        "not_found.html",
        context,
        status_code=status.HTTP_404_NOT_FOUND,
    )


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

    etcd_status = settings_map.get("etcd_status", "unknown")
    etcd_attention_states = {"down", "unavailable", "stale"}
    return {
        "ui_prefix": "/ui",
        "current_tab": current_tab,
        "auth_user": getattr(request.state, "auth_user", ""),
        "csrf_token": create_csrf_token(
            request.cookies.get(SESSION_COOKIE_NAME, ""),
            settings.auth_secret_key,
        ),
        "etcd_status": etcd_status,
        "etcd_needs_attention": etcd_status in etcd_attention_states,
        "etcd_last_sync_at": settings_map.get("etcd_last_sync_at"),
    }


def _verify_ui_csrf(request: Request, csrf_token: str = Form(default="")) -> None:
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if not verify_csrf_token(session_token, csrf_token, settings.auth_secret_key):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token.")


@router.get("")
async def overview(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)

    nodes = await node_service.list_nodes(session)
    events = await event_service.list_events(session, limit=12)
    preflight = await preflight_service.build_preflight_report(session, settings)

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
        "preflight": preflight,
    }
    context.update(await _base_context(request, session))
    return render_template(request, "overview.html", context)


@router.get("/network")
async def network_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    return RedirectResponse(url="/ui/nodes?view=map", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/nodes")
async def nodes_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    view_mode = (request.query_params.get("view") or "table").strip().lower()
    if view_mode not in {"table", "map"}:
        view_mode = "table"

    context = {
        "request": request,
        "title": "Nodes",
        "subtitle": "Live node health, connectivity, and quick actions",
    }
    context.update(await build_nodes_context(session, settings=settings, view_mode=view_mode))
    context.update(await _base_context(request, session))
    return render_template(request, "nodes.html", context)


@router.post("/nodes/join-command")
async def create_node_join_command(
    _csrf: None = Depends(_verify_ui_csrf),
    peer: str = Form(default=""),
    role: str = Form(default="auto"),
    ttl_seconds: int = Form(default=1800),
    join_port: int = Form(default=8010),
    session: AsyncSession = Depends(get_writable_db_session),
) -> dict[str, Any]:
    clean_peer = peer.strip()
    if not clean_peer:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Peer host or IP is required.")
    if role not in {"auto", "backend_server", "reverse_proxy"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role is invalid.")
    if ttl_seconds < 60 or ttl_seconds > 86400:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token lifetime must be between 60 and 86400 seconds.",
        )
    if join_port < 1 or join_port > 65535:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Join port is invalid.")

    token = await cluster_service.create_join_token(
        session,
        role=role,
        ttl_seconds=ttl_seconds,
        issued_by="ui.nodes.add_node",
    )
    settings_map = await cluster_settings.get_settings_map(session)
    repo_url = settings_map.get("github_repo_url", "https://github.com/Dinkum/uptime-mesh")
    return {
        "token_id": token.id,
        "role": token.role,
        "join_token": token.token,
        "expires_at": token.expires_at.isoformat(),
        "install_command": _install_join_command(
            clean_peer,
            token.role,
            join_port,
            repo_url,
        ),
    }


@router.get("/nodes/{node_id}")
async def node_detail_page(
    node_id: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    node = await node_service.get_node(session, node_id)
    if node is None:
        return await _not_found_response(
            request,
            session,
            title="Node Not Found",
            message=f"No node is registered with id {node_id}.",
            back_url="/ui/nodes",
            back_label="Back to Nodes",
        )

    context = {"request": request}
    context.update(await build_node_detail_context(session, settings=settings, node=node))
    context.update(await _base_context(request, session))
    return render_template(request, "node_detail.html", context)


@router.get("/roles")
async def roles_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    specs = await role_service.get_role_specs(session)
    placement = await role_service.get_latest_placement(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    if not isinstance(placement_rows, list):
        placement_rows = []
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
                "enabled": bool(spec.get("enabled", True)),
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
        "generated_at": _format_timestamp(
            _parse_datetime(placement.get("generated_at", "") if isinstance(placement, dict) else "")
        ),
        "warnings": placement.get("warnings", []) if isinstance(placement, dict) else [],
        "role_rows": role_rows,
    }
    context.update(await _base_context(request, session))
    return render_template(request, "roles.html", context)


@router.get("/roles/{role_name}")
async def role_detail_page(
    role_name: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    specs = await role_service.get_role_specs(session)
    if role_name not in specs:
        return await _not_found_response(
            request,
            session,
            title="Role Not Found",
            message=f"No role spec is registered for {role_name}.",
            back_url="/ui/roles",
            back_label="Back to Roles",
        )

    placement = await role_service.get_latest_placement(session)
    placement_rows = placement.get("roles", []) if isinstance(placement, dict) else []
    if not isinstance(placement_rows, list):
        placement_rows = []
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
    node_by_id = {node.id: build_node_summary(node, now) for node in nodes}
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
    return render_template(request, "role_detail.html", context)


@router.get("/workloads")
async def workloads_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    subtab = (request.query_params.get("tab") or "services").strip().lower()
    if subtab not in {"services", "replicas", "scheduler", "rollouts", "survivor", "state"}:
        subtab = "services"

    context = {
        "request": request,
        "title": "Workloads",
        "subtitle": "Services, replicas, and scheduler plan",
    }
    context.update(await build_workloads_context(session, subtab=subtab))
    context.update(await _base_context(request, session))
    return render_template(request, "workloads.html", context)


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
    context = {
        "request": request,
        "title": "Events",
        "subtitle": "Audit timeline and live stream",
    }
    context.update(await build_events_context(session))
    context.update(await _base_context(request, session))
    return render_template(request, "events.html", context)


@router.get("/infrastructure")
async def infrastructure_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    subtab = (request.query_params.get("tab") or "wireguard").strip().lower()
    if subtab not in {"wireguard", "discovery", "gateway", "monitoring", "cdn", "etcd", "swim"}:
        subtab = "wireguard"

    context = {
        "request": request,
        "title": "Infrastructure",
        "subtitle": "WireGuard, discovery, gateway, monitoring, and content cache",
    }
    context.update(await build_infrastructure_context(session, settings=settings, subtab=subtab))
    context.update(await _base_context(request, session))
    return render_template(request, "infrastructure.html", context)


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


async def _build_settings_context(
    request: Request,
    session: AsyncSession,
    *,
    active_section: str,
    password_success: str = "",
    password_error: str = "",
    repo_success: str = "",
    repo_error: str = "",
    routing_success: str = "",
    routing_error: str = "",
    routing_form: dict[str, Any] | None = None,
    provider_success: str = "",
    provider_error: str = "",
    github_repo_url_override: str | None = None,
) -> dict[str, Any]:
    return await build_settings_context(
        request,
        session,
        settings=settings,
        active_section=active_section,
        base_context=await _base_context(request, session),
        password_success=password_success,
        password_error=password_error,
        repo_success=repo_success,
        repo_error=repo_error,
        routing_success=routing_success,
        routing_error=routing_error,
        routing_form=routing_form,
        provider_success=provider_success,
        provider_error=provider_error,
        github_repo_url_override=github_repo_url_override,
    )


@router.get("/settings")
async def settings_page(request: Request, session: AsyncSession = Depends(get_db_session)) -> Any:
    password_updated = request.query_params.get("password_updated") == "1"
    repo_updated = request.query_params.get("repo_updated") == "1"
    application_updated = request.query_params.get("application_updated") == "1"
    domain_updated = request.query_params.get("domain_updated") == "1"
    domain_deleted = request.query_params.get("domain_deleted") == "1"
    provider_updated = request.query_params.get("provider_updated") == "1"
    active_section = (request.query_params.get("section") or "auth").strip().lower()
    if active_section not in {"auth", "routing", "providers", "support"}:
        active_section = "auth"
    routing_messages: list[str] = []
    if application_updated:
        routing_messages.append("Application saved.")
    if domain_updated:
        routing_messages.append("Domain route saved.")
    if domain_deleted:
        routing_messages.append("Domain route removed.")

    context = await _build_settings_context(
        request,
        session,
        active_section=active_section,
        password_success="Password updated successfully." if password_updated else "",
        repo_success="Repository URL updated successfully." if repo_updated else "",
        routing_success=" ".join(routing_messages),
        provider_success="Provider settings updated." if provider_updated else "",
    )
    return render_template(request, "settings.html", context)


@router.post("/settings/password")
async def change_password(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
) -> Any:
    error = ""
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
            session_epoch = await auth_service.get_session_epoch(session)
            session_token = create_session_token(
                username=auth_user,
                secret_key=settings.auth_secret_key,
                ttl_seconds=settings.auth_session_ttl_seconds,
                session_epoch=session_epoch,
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
        **(
            await _build_settings_context(
                request,
                session,
                active_section="auth",
                password_error=error,
            )
        ),
    }
    return render_template(request, "settings.html", context, status_code=status_code)


@router.post("/settings/security/revoke-sessions")
async def revoke_sessions(
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
) -> Any:
    await auth_service.revoke_all_sessions(session)
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@router.post("/settings/repo")
async def update_repo_url(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    github_repo_url: str = Form(default=""),
) -> Any:
    clean_url = github_repo_url.strip()
    error = ""
    status_code = status.HTTP_200_OK
    if not clean_url:
        error = "Repository URL is required."
        status_code = status.HTTP_400_BAD_REQUEST
    elif not clean_url.startswith("https://github.com/"):
        error = "Repository URL must start with https://github.com/."
        status_code = status.HTTP_400_BAD_REQUEST
    else:
        await cluster_settings.set_setting(session, "github_repo_url", clean_url)
        response = RedirectResponse(url="/ui/settings?repo_updated=1", status_code=status.HTTP_303_SEE_OTHER)
        return response

    context = await _build_settings_context(
        request,
        session,
        active_section="auth",
        repo_error=error,
        github_repo_url_override=clean_url or "https://github.com/Dinkum/uptime-mesh",
    )
    return render_template(request, "settings.html", context, status_code=status_code)


@router.post("/settings/routing/application")
async def upsert_application(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    app_id: str = Form(default=""),
    name: str = Form(default=""),
    description: str = Form(default=""),
    target_service_id: str = Form(default=""),
    default_path: str = Form(default="/"),
    enabled: str = Form(default="off"),
) -> Any:
    ok, message = await applications_service.upsert_application(
        session,
        app_id=app_id,
        name=name,
        description=description,
        target_service_id=target_service_id,
        default_path=default_path,
        enabled=_as_form_bool(enabled),
    )
    if ok:
        return RedirectResponse(
            url="/ui/settings?section=routing&application_updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    context = await _build_settings_context(
        request,
        session,
        active_section="routing",
        routing_error=message or "Failed to save application.",
        routing_form={
            "app_id": app_id,
            "name": name,
            "description": description,
            "target_service_id": target_service_id,
            "default_path": default_path,
            "application_enabled": _as_form_bool(enabled),
        },
    )
    return render_template(
        request,
        "settings.html",
        context,
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@router.post("/settings/routing/domain")
async def upsert_domain_route(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    route_id: str = Form(default=""),
    domain: str = Form(default=""),
    application_id: str = Form(default=""),
    path: str = Form(default="/"),
    enabled: str = Form(default="off"),
) -> Any:
    ok, message = await applications_service.upsert_domain_route(
        session,
        route_id=route_id,
        domain=domain,
        application_id=application_id,
        path=path,
        enabled=_as_form_bool(enabled),
    )
    if ok:
        return RedirectResponse(
            url="/ui/settings?section=routing&domain_updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    context = await _build_settings_context(
        request,
        session,
        active_section="routing",
        routing_error=message or "Failed to save domain route.",
        routing_form={
            "route_id": route_id,
            "domain": domain,
            "application_id": application_id,
            "path": path,
            "domain_enabled": _as_form_bool(enabled),
        },
    )
    return render_template(
        request,
        "settings.html",
        context,
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@router.post("/settings/routing/domain/delete")
async def delete_domain_route(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    route_id: str = Form(default=""),
) -> Any:
    clean_route_id = route_id.strip()
    if not clean_route_id:
        context = await _build_settings_context(
            request,
            session,
            active_section="routing",
            routing_error="Domain route id is required.",
        )
        return render_template(
            request,
            "settings.html",
            context,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    deleted = await applications_service.delete_domain_route(session, route_id=clean_route_id)
    if deleted:
        return RedirectResponse(
            url="/ui/settings?section=routing&domain_deleted=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    context = await _build_settings_context(
        request,
        session,
        active_section="routing",
        routing_error="Domain route was not found.",
    )
    return render_template(
        request,
        "settings.html",
        context,
        status_code=status.HTTP_404_NOT_FOUND,
    )


@router.post("/settings/providers")
async def update_provider_settings(
    request: Request,
    _csrf: None = Depends(_verify_ui_csrf),
    session: AsyncSession = Depends(get_writable_db_session),
    provider_openai_api_key: str = Form(default=""),
    provider_cloudflare_api_token: str = Form(default=""),
    provider_cloudflare_zone_id: str = Form(default=""),
    provider_hetzner_api_token: str = Form(default=""),
    provider_scaleway_api_token: str = Form(default=""),
    provider_online_api_token: str = Form(default=""),
    domain_ingress_target: str = Form(default=""),
    clear_provider_openai_api_key: str = Form(default="off"),
    clear_provider_cloudflare_api_token: str = Form(default="off"),
    clear_provider_hetzner_api_token: str = Form(default="off"),
    clear_provider_scaleway_api_token: str = Form(default="off"),
    clear_provider_online_api_token: str = Form(default="off"),
) -> Any:
    updates: dict[str, str] = {
        "provider_cloudflare_zone_id": provider_cloudflare_zone_id.strip(),
        "domain_ingress_target": domain_ingress_target.strip(),
    }
    token_values = {
        "provider_openai_api_key": provider_openai_api_key.strip(),
        "provider_cloudflare_api_token": provider_cloudflare_api_token.strip(),
        "provider_hetzner_api_token": provider_hetzner_api_token.strip(),
        "provider_scaleway_api_token": provider_scaleway_api_token.strip(),
        "provider_online_api_token": provider_online_api_token.strip(),
    }
    clear_flags = {
        "provider_openai_api_key": _as_form_bool(clear_provider_openai_api_key),
        "provider_cloudflare_api_token": _as_form_bool(clear_provider_cloudflare_api_token),
        "provider_hetzner_api_token": _as_form_bool(clear_provider_hetzner_api_token),
        "provider_scaleway_api_token": _as_form_bool(clear_provider_scaleway_api_token),
        "provider_online_api_token": _as_form_bool(clear_provider_online_api_token),
    }
    for key, value in token_values.items():
        if clear_flags.get(key):
            updates[key] = ""
        elif value:
            updates[key] = value
    await cluster_settings.upsert_settings(session, updates, sync_file=True)
    return RedirectResponse(
        url="/ui/settings?section=providers&provider_updated=1",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{path:path}")
async def ui_not_found(
    path: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Any:
    return await _not_found_response(
        request,
        session,
        title="Page Not Found",
        message=f"No console page exists at /ui/{path}.",
        back_url="/ui",
        back_label="Back to Overview",
    )
