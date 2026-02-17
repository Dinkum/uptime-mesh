from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Replica(TimestampMixin, Base):
    __tablename__ = "replicas"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_id: Mapped[str] = mapped_column(String(64), ForeignKey("services.id"))
    node_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.id"))
    desired_state: Mapped[str] = mapped_column(String(32), default="running")
    status: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
