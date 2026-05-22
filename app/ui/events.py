from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.formatting import format_timestamp, format_value, parse_datetime
from app.services import events as event_service


def format_event_field_value(key: str, value: Any) -> str:
    if isinstance(value, str) and key.endswith("_at"):
        parsed = parse_datetime(value)
        if parsed is not None:
            return format_timestamp(parsed)
    return format_value(value)


def event_field_summary(fields: Any, *, max_items: int = 4) -> str:
    if not isinstance(fields, dict):
        return "-"
    skip = {"node_id"}
    priority_keys = [
        "reason",
        "action",
        "state",
        "role",
        "target_node_id",
        "peer_node_id",
        "service_id",
        "replica_id",
        "error_type",
        "error",
    ]
    rendered: list[str] = []
    used: set[str] = set()
    for key in priority_keys:
        value = fields.get(key)
        if value in (None, "", []):
            continue
        rendered.append(f"{key}: {format_value(value)}")
        used.add(key)
        if len(rendered) >= max_items:
            return " | ".join(rendered)
    for key in sorted(fields.keys()):
        if key in used or key in skip:
            continue
        value = fields.get(key)
        if value in (None, "", []):
            continue
        rendered.append(f"{key}: {format_value(value)}")
        if len(rendered) >= max_items:
            break
    return " | ".join(rendered) if rendered else "-"


async def build_events_context(session: AsyncSession) -> dict[str, Any]:
    events = await event_service.list_events(session, limit=50)
    return {
        "events": [
            {
                "id": event.id,
                "name": event.name,
                "level": event.level,
                "category": event.category,
                "created_at": format_timestamp(event.created_at),
                "fields": {
                    str(key): format_event_field_value(str(key), value)
                    for key, value in (event.fields or {}).items()
                },
            }
            for event in events
        ],
        "events_stream_since": events[0].created_at.isoformat() if events else "",
    }
