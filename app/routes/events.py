from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import AsyncIterator, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session, get_sessionmaker, get_writable_db_session
from app.models.event import Event
from app.schemas.events import EventCreate, EventOut
from app.services import events as event_service

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=List[EventOut])
async def list_events(
    limit: int = 200,
    category: Optional[str] = None,
    session: AsyncSession = Depends(get_db_session),
) -> List[EventOut]:
    bounded_limit = max(1, min(limit, 1000))
    events = await event_service.list_events(session, limit=bounded_limit, category=category)
    return [EventOut.model_validate(event) for event in events]


@router.post("", response_model=EventOut, status_code=status.HTTP_201_CREATED)
async def create_event(
    payload: EventCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> EventOut:
    event_id = payload.id or str(uuid4())
    if payload.id and await event_service.get_event(session, payload.id):
        raise HTTPException(status_code=409, detail="Event id already exists")
    event = await event_service.record_event(
        session,
        event_id=event_id,
        category=payload.category,
        name=payload.name,
        level=payload.level,
        fields=payload.fields,
    )
    await session.commit()
    await session.refresh(event)
    return EventOut.model_validate(event)


@router.get("/stream")
async def stream_events(
    since: Optional[datetime] = None,
) -> StreamingResponse:
    settings = get_settings()
    sessionmaker = get_sessionmaker(settings.database_url)

    async def event_generator() -> AsyncIterator[str]:
        last_seen = since
        while True:
            async with sessionmaker() as session:
                query = select(Event).order_by(Event.created_at.asc()).limit(200)
                if last_seen is not None:
                    query = query.where(Event.created_at > last_seen)
                result = await session.execute(query)
                events = list(result.scalars().all())

            for event in events:
                payload = EventOut.model_validate(event).model_dump()
                payload_json = json.dumps(payload, default=str)
                yield f"event: event\ndata: {payload_json}\n\n"
                last_seen = event.created_at

            await asyncio.sleep(1.5)

    stream_response = StreamingResponse(event_generator(), media_type="text/event-stream")
    stream_response.headers["Cache-Control"] = "no-cache"
    return stream_response
