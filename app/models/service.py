from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Service(TimestampMixin, Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    spec: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    generation: Mapped[int] = mapped_column(default=1)
