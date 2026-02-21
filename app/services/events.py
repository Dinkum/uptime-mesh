from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.event import Event

_logger = get_logger("services.events")


async def list_events(
    session: AsyncSession,
    limit: int = 200,
    category: Optional[str] = None,
) -> List[Event]:
    query = select(Event).order_by(Event.created_at.desc())
    if category:
        query = query.where(Event.category == category)
    query = query.limit(limit)
    result = await session.execute(query)
    return list(result.scalars().all())


def _event_matches_node(event: Event, node_id: str) -> bool:
    fields = event.fields if isinstance(event.fields, dict) else {}
    candidates = (
        "node_id",
        "target_node_id",
        "source_node_id",
        "peer_node_id",
        "member_name",
    )
    for key in candidates:
        value = fields.get(key)
        if isinstance(value, str) and value.strip() == node_id:
            return True
    return False


async def list_events_for_node(
    session: AsyncSession,
    *,
    node_id: str,
    limit: int = 40,
    search_limit: int = 400,
) -> List[Event]:
    if not node_id.strip():
        return []
    rows = await list_events(session, limit=max(limit, search_limit))
    matched: list[Event] = []
    for row in rows:
        if _event_matches_node(row, node_id):
            matched.append(row)
            if len(matched) >= limit:
                break
    return matched


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


async def prune_old_events(
    session: AsyncSession,
    *,
    retention_days: int,
    batch_size: int = 5000,
    max_batches: int = 20,
) -> int:
    if retention_days <= 0:
        return 0
    capped_batch = max(100, min(batch_size, 100000))
    capped_batches = max(1, min(max_batches, 200))
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    total_deleted = 0
    for _ in range(capped_batches):
        id_rows = await session.execute(
            select(Event.id)
            .where(Event.created_at < cutoff)
            .order_by(Event.created_at.asc())
            .limit(capped_batch)
        )
        ids = [str(row[0]) for row in id_rows.all() if row and row[0]]
        if not ids:
            break

        result = await session.execute(
            delete(Event).where(Event.id.in_(ids)).execution_options(synchronize_session=False)
        )
        deleted = int(result.rowcount or 0)
        if deleted <= 0:
            deleted = len(ids)
        total_deleted += deleted
        await session.commit()

        if len(ids) < capped_batch:
            break

    if total_deleted > 0:
        _logger.info(
            "events.prune",
            "Pruned old events by retention policy",
            retention_days=retention_days,
            deleted=total_deleted,
            cutoff=cutoff.isoformat(),
        )
    return total_deleted
