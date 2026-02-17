from __future__ import annotations

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class RouterAssignment(TimestampMixin, Base):
    __tablename__ = "router_assignments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.id"), index=True)
    primary_router_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.id"))
    secondary_router_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.id"))
