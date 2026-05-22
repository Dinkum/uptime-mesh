from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.formatting import format_timestamp, parse_datetime
from app.services import applications as applications_service
from app.services import auth as auth_service
from app.services import cluster_settings
from app.services import providers as provider_service
from app.services import services as service_service
from app.services import snapshots as snapshot_service
from app.services import support_bundles as support_bundle_service


def dns_record_suggestion(domain: str, ingress_target: str) -> dict[str, str]:
    clean_domain = str(domain or "").strip().lower()
    clean_target = str(ingress_target or "").strip()
    if not clean_domain or not clean_target:
        return {"domain": clean_domain, "record_type": "-", "record_value": "-", "instructions": ""}
    try:
        parsed_ip = ipaddress.ip_address(clean_target)
        record_type = "AAAA" if parsed_ip.version == 6 else "A"
        return {
            "domain": clean_domain,
            "record_type": record_type,
            "record_value": clean_target,
            "instructions": f"Create a {record_type} record for {clean_domain} -> {clean_target}.",
        }
    except ValueError:
        return {
            "domain": clean_domain,
            "record_type": "CNAME",
            "record_value": clean_target.rstrip("."),
            "instructions": (
                f"Create a CNAME record for {clean_domain} -> {clean_target.rstrip('.')}. "
                "If your DNS provider forbids root CNAMEs, use an A/AAAA flattening option."
            ),
        }


async def build_settings_context(
    request: Request,
    session: AsyncSession,
    *,
    settings: Settings,
    active_section: str,
    base_context: dict[str, Any],
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
    settings_map = await cluster_settings.get_settings_map(session)
    username = await auth_service.get_username(session)
    security_summary = await auth_service.get_security_summary(session)
    applications: list[Any] = []
    domain_routes: list[Any] = []
    domain_bindings: list[dict[str, Any]] = []
    service_options: list[dict[str, str]] = []
    ingress_target = str(settings_map.get("domain_ingress_target", "")).strip()
    dns_record_rows: list[dict[str, Any]] = []
    if active_section == "routing":
        applications, domain_routes = await applications_service.ensure_catalog_defaults(session)
        domain_bindings = applications_service.build_domain_bindings(
            applications=applications,
            domain_routes=domain_routes,
        )
        services = await service_service.list_services(session, limit=2000)
        service_options = [
            {"id": str(service.id), "name": str(service.name)}
            for service in sorted(services, key=lambda item: str(item.name).lower())
        ]
        for binding in domain_bindings:
            domain = str(binding.get("domain") or "").strip().lower()
            if not domain:
                continue
            suggestion = dns_record_suggestion(domain, ingress_target)
            dns_record_rows.append(
                {
                    "domain": domain,
                    "application_id": str(binding.get("application_id") or ""),
                    "application_name": str(binding.get("application_name") or "-"),
                    "application_target_service_id": str(
                        binding.get("application_target_service_id") or ""
                    ),
                    "route_enabled": bool(binding.get("route_enabled", False)),
                    "application_enabled": bool(binding.get("application_enabled", False)),
                    "routing_ready": bool(binding.get("routing_ready", False)),
                    "record_type": suggestion["record_type"],
                    "record_value": suggestion["record_value"],
                    "instructions": suggestion["instructions"],
                }
            )
        dns_record_rows.sort(key=lambda row: row["domain"])

    snapshots: list[Any] = []
    bundles: list[Any] = []
    if active_section == "support":
        snapshots = await snapshot_service.list_snapshots(session)
        bundles = await support_bundle_service.list_support_bundles(session)

    provider_secret_keys = [
        "provider_openai_api_key",
        "provider_cloudflare_api_token",
        "provider_hetzner_api_token",
        "provider_scaleway_api_token",
        "provider_online_api_token",
    ]
    provider_configured = {
        key: bool(str(settings_map.get(key, "")).strip()) for key in provider_secret_keys
    }
    provider_capabilities = []
    if active_section == "providers":
        provider_capabilities = await provider_service.list_capabilities(session)

    context = {
        "request": request,
        "title": "Settings",
        "subtitle": "Authentication, routing, provider integrations, and support tools",
        "settings_section": active_section,
        "username": username,
        "security_summary": security_summary,
        "password_updated_at": format_timestamp(
            parse_datetime(security_summary.get("password_updated_at"))
        ),
        "node_cert_validity_days": settings.node_cert_validity_days,
        "password_success": password_success,
        "password_error": password_error,
        "repo_success": repo_success,
        "repo_error": repo_error,
        "routing_success": routing_success,
        "routing_error": routing_error,
        "routing_form": routing_form or {},
        "provider_success": provider_success,
        "provider_error": provider_error,
        "github_repo_url": (
            github_repo_url_override
            if github_repo_url_override is not None
            else settings_map.get("github_repo_url", "https://github.com/Dinkum/uptime-mesh")
        ),
        "applications": applications,
        "domain_routes": domain_routes,
        "domain_bindings": domain_bindings,
        "service_options": service_options,
        "domain_ingress_target": ingress_target,
        "dns_record_rows": dns_record_rows,
        "provider_configured": provider_configured,
        "provider_capabilities": provider_capabilities,
        "provider_cloudflare_zone_id": settings_map.get("provider_cloudflare_zone_id", ""),
        "snapshots": snapshots,
        "bundles": bundles,
    }
    context.update(base_context)
    return context
