from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.router_assignments import RouterAssignmentCreate, RouterAssignmentOut
from app.services import nodes as node_service
from app.services import router_assignments as router_assignment_service

router = APIRouter(prefix="/router-assignments", tags=["router-assignments"])


@router.get("", response_model=List[RouterAssignmentOut])
async def list_router_assignments(
    session: AsyncSession = Depends(get_db_session),
) -> List[RouterAssignmentOut]:
    assignments = await router_assignment_service.list_router_assignments(session)
    return [RouterAssignmentOut.model_validate(assignment) for assignment in assignments]


@router.get("/{assignment_id}", response_model=RouterAssignmentOut)
async def get_router_assignment(
    assignment_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> RouterAssignmentOut:
    assignment = await router_assignment_service.get_router_assignment(session, assignment_id)
    if assignment is None:
        raise HTTPException(status_code=404, detail="Router assignment not found")
    return RouterAssignmentOut.model_validate(assignment)


@router.post("", response_model=RouterAssignmentOut, status_code=status.HTTP_201_CREATED)
async def create_router_assignment(
    payload: RouterAssignmentCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> RouterAssignmentOut:
    if await router_assignment_service.get_router_assignment(session, payload.id):
        raise HTTPException(status_code=409, detail="Router assignment id already exists")
    if payload.primary_router_id == payload.secondary_router_id:
        raise HTTPException(status_code=400, detail="Primary and secondary router must differ")
    for node_id in (payload.node_id, payload.primary_router_id, payload.secondary_router_id):
        if await node_service.get_node(session, node_id) is None:
            raise HTTPException(status_code=404, detail=f"Node not found: {node_id}")
    assignment = await router_assignment_service.create_router_assignment(session, payload)
    return RouterAssignmentOut.model_validate(assignment)
