from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import JSON, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Event(TimestampMixin, Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_created_at", "created_at"),
        Index("ix_events_level_created_at", "level", "created_at"),
        Index("ix_events_node_id_created_at", "node_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128))
    level: Mapped[str] = mapped_column(String(16))
    node_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    fields: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
