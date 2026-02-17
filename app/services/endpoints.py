from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.endpoint import Endpoint
from app.schemas.endpoints import EndpointCreate, EndpointUpdate
from app.services.events import record_event

_logger = get_logger("services.endpoints")


async def list_endpoints(session: AsyncSession, limit: int = 200) -> List[Endpoint]:
    result = await session.execute(select(Endpoint).limit(limit))
    return list(result.scalars().all())


async def get_endpoint(session: AsyncSession, endpoint_id: str) -> Optional[Endpoint]:
    result = await session.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    return result.scalar_one_or_none()


async def create_endpoint(session: AsyncSession, payload: EndpointCreate) -> Endpoint:
    endpoint = Endpoint(
        id=payload.id,
        replica_id=payload.replica_id,
        address=payload.address,
        port=payload.port,
        healthy=payload.healthy,
    )
    session.add(endpoint)
    await record_event(
        session,
        event_id=str(uuid4()),
        category="endpoints",
        name="endpoint.create",
        level="INFO",
        fields={"endpoint_id": endpoint.id, "replica_id": endpoint.replica_id},
    )
    await session.commit()
    await session.refresh(endpoint)
    _logger.info("endpoints.create", "Created endpoint", endpoint_id=endpoint.id)
    return endpoint


async def update_endpoint(
    session: AsyncSession,
    endpoint: Endpoint,
    payload: EndpointUpdate,
) -> Endpoint:
    changed = False
    if payload.healthy is not None:
        endpoint.healthy = payload.healthy
        endpoint.last_checked_at = datetime.now(timezone.utc)
        changed = True

    if changed:
        await record_event(
            session,
            event_id=str(uuid4()),
            category="endpoints",
            name="endpoint.update",
            level="INFO",
            fields={"endpoint_id": endpoint.id, "healthy": endpoint.healthy},
        )

    await session.commit()
    await session.refresh(endpoint)
    return endpoint
