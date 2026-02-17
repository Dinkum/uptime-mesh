from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.models.base import Base, TimestampMixin


class Endpoint(TimestampMixin, Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    replica_id: Mapped[str] = mapped_column(String(64), ForeignKey("replicas.id"))
    address: Mapped[str] = mapped_column(String(128))
    port: Mapped[int] = mapped_column(Integer)
    healthy: Mapped[bool] = mapped_column(Boolean, default=True)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        server_default=None,
        onupdate=func.now(),
    )
