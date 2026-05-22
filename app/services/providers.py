from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.provider import ProviderAccount, ProviderAction, ProviderResource
from app.schemas.providers import (
    ProviderAccountCreate,
    ProviderAccountOut,
    ProviderActionOut,
    ProviderCapabilityOut,
    ProviderResourceOut,
    ProviderSummaryOut,
)
from app.services import cluster_settings
from app.utils import sanitize_label


@dataclass(frozen=True)
class ProviderDriver:
    provider: str
    capabilities: tuple[str, ...]
    required_settings: tuple[str, ...]

    def inspect(self, settings_map: dict[str, str]) -> ProviderCapabilityOut:
        missing = [key for key in self.required_settings if not settings_map.get(key, "").strip()]
        return ProviderCapabilityOut(
            provider=self.provider,
            configured=not missing,
            capabilities=list(self.capabilities),
            missing_settings=missing,
        )


DRIVERS: tuple[ProviderDriver, ...] = (
    ProviderDriver(
        provider="cloudflare",
        capabilities=("dns.plan", "dns.apply", "dns.rollback"),
        required_settings=("provider_cloudflare_api_token", "provider_cloudflare_zone_id"),
    ),
    ProviderDriver(
        provider="hetzner",
        capabilities=("server.observe", "server.plan", "server.apply", "server.rollback"),
        required_settings=("provider_hetzner_api_token",),
    ),
    ProviderDriver(
        provider="scaleway",
        capabilities=("server.observe", "server.plan", "server.apply", "server.rollback"),
        required_settings=("provider_scaleway_api_token",),
    ),
    ProviderDriver(
        provider="online",
        capabilities=("server.observe", "server.plan", "server.apply", "server.rollback"),
        required_settings=("provider_online_api_token",),
    ),
    ProviderDriver(
        provider="openai",
        capabilities=("incident.summarize", "operator.assist"),
        required_settings=("provider_openai_api_key",),
    ),
)

_SENSITIVE_CONFIG_FRAGMENTS = ("token", "key", "secret", "password")


def _safe_config(config: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in config.items():
        key_text = str(key)
        if any(fragment in key_text.lower() for fragment in _SENSITIVE_CONFIG_FRAGMENTS):
            safe[key_text] = "configured" if str(value).strip() else ""
        else:
            safe[key_text] = value
    return safe


def account_out(account: ProviderAccount) -> ProviderAccountOut:
    return ProviderAccountOut(
        id=account.id,
        provider=account.provider,
        display_name=account.display_name,
        enabled=account.enabled,
        config=_safe_config(account.config if isinstance(account.config, dict) else {}),
        created_at=account.created_at,
        updated_at=account.updated_at,
    )


async def list_capabilities(session: AsyncSession) -> list[ProviderCapabilityOut]:
    settings_map = await cluster_settings.get_settings_map(session)
    return [driver.inspect(settings_map) for driver in DRIVERS]


async def list_accounts(session: AsyncSession, limit: int = 200) -> list[ProviderAccount]:
    result = await session.execute(
        select(ProviderAccount).order_by(ProviderAccount.provider.asc()).limit(limit)
    )
    return list(result.scalars().all())


async def list_resources(session: AsyncSession, limit: int = 500) -> list[ProviderResource]:
    result = await session.execute(
        select(ProviderResource).order_by(ProviderResource.provider.asc()).limit(limit)
    )
    return list(result.scalars().all())


async def list_actions(session: AsyncSession, limit: int = 500) -> list[ProviderAction]:
    result = await session.execute(
        select(ProviderAction).order_by(ProviderAction.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def get_summary(session: AsyncSession) -> ProviderSummaryOut:
    capabilities = await list_capabilities(session)
    accounts = await list_accounts(session)
    resources = await list_resources(session)
    actions = await list_actions(session)
    return ProviderSummaryOut(
        capabilities=capabilities,
        accounts=[account_out(account) for account in accounts],
        resources=[ProviderResourceOut.model_validate(resource) for resource in resources],
        actions=[ProviderActionOut.model_validate(action) for action in actions],
    )


async def upsert_account(
    session: AsyncSession,
    payload: ProviderAccountCreate,
) -> ProviderAccount:
    provider = sanitize_label(payload.provider, max_len=64)
    if not provider:
        raise ValueError("provider is required")
    account_id = sanitize_label(payload.id, max_len=64)
    if not account_id:
        raise ValueError("provider account id is required")
    account = await session.get(ProviderAccount, account_id)
    config: dict[str, Any] = dict(payload.config or {})
    if account is None:
        account = ProviderAccount(
            id=account_id,
            provider=provider,
            display_name=payload.display_name.strip() or account_id,
            enabled=payload.enabled,
            config=config,
        )
        session.add(account)
    else:
        account.provider = provider
        account.display_name = payload.display_name.strip() or account_id
        account.enabled = payload.enabled
        account.config = config
    await session.commit()
    await session.refresh(account)
    return account
