from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy import Boolean, JSON, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ProviderAccount(TimestampMixin, Base):
    __tablename__ = "provider_accounts"
    __table_args__ = (
        Index("ix_provider_accounts_provider", "provider"),
        Index("ix_provider_accounts_enabled", "enabled"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class ProviderResource(TimestampMixin, Base):
    __tablename__ = "provider_resources"
    __table_args__ = (
        Index("ix_provider_resources_account_id", "account_id"),
        Index("ix_provider_resources_provider_kind", "provider", "resource_kind"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64), ForeignKey("provider_accounts.id"))
    provider: Mapped[str] = mapped_column(String(64), index=True)
    resource_kind: Mapped[str] = mapped_column(String(64))
    external_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    desired: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    observed: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class ProviderAction(TimestampMixin, Base):
    __tablename__ = "provider_actions"
    __table_args__ = (
        Index("ix_provider_actions_account_id", "account_id"),
        Index("ix_provider_actions_resource_id", "resource_id"),
        Index("ix_provider_actions_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[str] = mapped_column(String(64), ForeignKey("provider_accounts.id"))
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("provider_resources.id"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="planned")
    plan: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
