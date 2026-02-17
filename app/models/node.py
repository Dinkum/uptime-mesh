from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Node(TimestampMixin, Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    roles: Mapped[List[str]] = mapped_column(JSON, default=list)
    labels: Mapped[Dict[str, str]] = mapped_column(JSON, default=dict)
    mesh_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    api_endpoint: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    lease_token_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    identity_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    identity_cert_pem: Mapped[Optional[str]] = mapped_column(String(8192), nullable=True)
    identity_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
