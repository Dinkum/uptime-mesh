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
    async with _logger.operation("endpoint.list", "Listing endpoints", limit=limit) as op:
        result = await session.execute(select(Endpoint).limit(limit))
        endpoints = list(result.scalars().all())
        op.step("db.select", "Fetched endpoints", count=len(endpoints))
        return endpoints


async def get_endpoint(session: AsyncSession, endpoint_id: str) -> Optional[Endpoint]:
    result = await session.execute(select(Endpoint).where(Endpoint.id == endpoint_id))
    return result.scalar_one_or_none()


async def create_endpoint(session: AsyncSession, payload: EndpointCreate) -> Endpoint:
    async with _logger.operation(
        "endpoint.create",
        "Creating endpoint",
        endpoint_id=payload.id,
        replica_id=payload.replica_id,
        address=payload.address,
        port=payload.port,
    ) as op:
        endpoint = Endpoint(
            id=payload.id,
            replica_id=payload.replica_id,
            address=payload.address,
            port=payload.port,
            healthy=payload.healthy,
        )
        session.add(endpoint)
        op.step("db.insert", "Prepared endpoint row")
        await record_event(
            session,
            event_id=str(uuid4()),
            category="endpoints",
            name="endpoint.create",
            level="INFO",
            fields={"endpoint_id": endpoint.id, "replica_id": endpoint.replica_id},
        )
        op.step("event.record", "Recorded endpoint create event")
        await session.commit()
        await session.refresh(endpoint)
        op.step("db.commit", "Committed endpoint create transaction")
        _logger.info("endpoints.create", "Created endpoint", endpoint_id=endpoint.id)
        return endpoint


async def update_endpoint(
    session: AsyncSession,
    endpoint: Endpoint,
    payload: EndpointUpdate,
) -> Endpoint:
    async with _logger.operation(
        "endpoint.update",
        "Updating endpoint",
        endpoint_id=endpoint.id,
    ) as op:
        changed = False
        if payload.healthy is not None:
            endpoint.healthy = payload.healthy
            endpoint.last_checked_at = datetime.now(timezone.utc)
            changed = True
            op.step("health.update", "Updated endpoint health", healthy=endpoint.healthy)

        if changed:
            await record_event(
                session,
                event_id=str(uuid4()),
                category="endpoints",
                name="endpoint.update",
                level="INFO",
                fields={"endpoint_id": endpoint.id, "healthy": endpoint.healthy},
            )
            op.step("event.record", "Recorded endpoint update event")
        else:
            op.step("change.none", "No endpoint fields changed")

        await session.commit()
        await session.refresh(endpoint)
        op.step("db.commit", "Committed endpoint update transaction")
        return endpoint
