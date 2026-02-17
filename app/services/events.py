from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.event import Event

_logger = get_logger("services.events")


async def list_events(
    session: AsyncSession,
    limit: int = 200,
    category: Optional[str] = None,
) -> List[Event]:
    query = select(Event).order_by(Event.created_at.desc()).limit(limit)
    if category:
        query = query.where(Event.category == category)
    result = await session.execute(query)
    return list(result.scalars().all())


async def get_event(session: AsyncSession, event_id: str) -> Optional[Event]:
    result = await session.execute(select(Event).where(Event.id == event_id))
    return result.scalar_one_or_none()


async def record_event(
    session: AsyncSession,
    event_id: str,
    category: str,
    name: str,
    level: str,
    fields: Optional[Dict[str, Any]] = None,
) -> Event:
    event = Event(
        id=event_id,
        category=category,
        name=name,
        level=level,
        fields=fields or {},
    )
    session.add(event)
    _logger.info(
        "events.record",
        "Recorded event",
        event_id=event.id,
        category=category,
        name=name,
        level=level,
    )
    return event
