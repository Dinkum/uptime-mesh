from __future__ import annotations

from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.router_assignment import RouterAssignment
from app.schemas.router_assignments import RouterAssignmentCreate
from app.services.events import record_event

_logger = get_logger("services.router_assignments")


async def list_router_assignments(
    session: AsyncSession, limit: int = 200
) -> List[RouterAssignment]:
    async with _logger.operation(
        "router_assignment.list",
        "Listing router assignments",
        limit=limit,
    ) as op:
        result = await session.execute(select(RouterAssignment).limit(limit))
        rows = list(result.scalars().all())
        op.step("db.select", "Fetched router assignments", count=len(rows))
        return rows


async def get_router_assignment(
    session: AsyncSession,
    assignment_id: str,
) -> Optional[RouterAssignment]:
    result = await session.execute(
        select(RouterAssignment).where(RouterAssignment.id == assignment_id)
    )
    return result.scalar_one_or_none()


async def create_router_assignment(
    session: AsyncSession,
    payload: RouterAssignmentCreate,
) -> RouterAssignment:
    async with _logger.operation(
        "router_assignment.create",
        "Creating router assignment",
        assignment_id=payload.id,
        node_id=payload.node_id,
    ) as op:
        assignment = RouterAssignment(
            id=payload.id,
            node_id=payload.node_id,
            primary_router_id=payload.primary_router_id,
            secondary_router_id=payload.secondary_router_id,
        )
        session.add(assignment)
        op.step(
            "db.insert",
            "Prepared router assignment row",
            primary_router_id=payload.primary_router_id,
            secondary_router_id=payload.secondary_router_id,
        )
        await record_event(
            session,
            event_id=str(uuid4()),
            category="router_assignments",
            name="router_assignment.create",
            level="INFO",
            fields={"assignment_id": assignment.id, "node_id": assignment.node_id},
        )
        op.step("event.record", "Recorded router assignment create event")
        await session.commit()
        await session.refresh(assignment)
        op.step("db.commit", "Committed router assignment transaction")
        _logger.info(
            "router_assignments.create", "Created router assignment", assignment_id=assignment.id
        )
        return assignment
