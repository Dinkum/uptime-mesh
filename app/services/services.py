from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.service import Service
from app.schemas.services import ServiceCreate, ServiceUpdate
from app.services.events import record_event

_logger = get_logger("services.services")


async def list_services(session: AsyncSession, limit: int = 100) -> List[Service]:
    result = await session.execute(select(Service).limit(limit))
    return list(result.scalars().all())


async def get_service(session: AsyncSession, service_id: str) -> Optional[Service]:
    result = await session.execute(select(Service).where(Service.id == service_id))
    return result.scalar_one_or_none()


async def get_service_by_name(session: AsyncSession, name: str) -> Optional[Service]:
    result = await session.execute(select(Service).where(Service.name == name))
    return result.scalar_one_or_none()


async def create_service(session: AsyncSession, payload: ServiceCreate) -> Service:
    service = Service(
        id=payload.id,
        name=payload.name,
        description=payload.description,
        spec=payload.spec,
    )
    session.add(service)
    await record_event(
        session,
        event_id=str(uuid4()),
        category="services",
        name="service.create",
        level="INFO",
        fields={"service_id": payload.id, "name": payload.name},
    )
    await session.commit()
    await session.refresh(service)
    _logger.info("services.create", "Created service", service_id=service.id)
    return service


async def update_service(
    session: AsyncSession,
    service: Service,
    payload: ServiceUpdate,
) -> Service:
    changed = False
    if payload.description is not None:
        service.description = payload.description
        changed = True
    if payload.spec is not None:
        service.spec = payload.spec
        service.generation += 1
        changed = True

    if changed:
        await record_event(
            session,
            event_id=str(uuid4()),
            category="services",
            name="service.update",
            level="INFO",
            fields={"service_id": service.id},
        )

    await session.commit()
    await session.refresh(service)
    return service


async def rollout_service(session: AsyncSession, service: Service) -> Service:
    service.generation += 1
    spec = dict(service.spec or {})
    spec["rollout_requested_at"] = datetime.now(timezone.utc).isoformat()
    service.spec = spec
    await record_event(
        session,
        event_id=str(uuid4()),
        category="services",
        name="service.rollout",
        level="INFO",
        fields={"service_id": service.id, "generation": service.generation},
    )
    await session.commit()
    await session.refresh(service)
    return service


async def rollback_service(
    session: AsyncSession,
    service: Service,
    target_generation: Optional[int],
) -> Service:
    if target_generation is not None and target_generation > 0:
        service.generation = target_generation
    elif service.generation > 1:
        service.generation -= 1

    spec = dict(service.spec or {})
    spec["rollback_requested_at"] = datetime.now(timezone.utc).isoformat()
    service.spec = spec
    await record_event(
        session,
        event_id=str(uuid4()),
        category="services",
        name="service.rollback",
        level="INFO",
        fields={"service_id": service.id, "generation": service.generation},
    )
    await session.commit()
    await session.refresh(service)
    return service
