from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.scheduler import SchedulerBulkResultOut, SchedulerResultOut
from app.services import scheduler as scheduler_service

router = APIRouter(prefix="/scheduler", tags=["scheduler"])


@router.get("/plan/services/{service_id}", response_model=SchedulerResultOut)
async def plan_service_reconcile(
    service_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> SchedulerResultOut:
    try:
        return await scheduler_service.reconcile_service(
            session, service_id=service_id, dry_run=True
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/reconcile/services/{service_id}", response_model=SchedulerResultOut)
async def reconcile_service(
    service_id: str,
    session: AsyncSession = Depends(get_writable_db_session),
) -> SchedulerResultOut:
    try:
        return await scheduler_service.reconcile_service(
            session, service_id=service_id, dry_run=False
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/reconcile/all", response_model=SchedulerBulkResultOut)
async def reconcile_all_services(
    session: AsyncSession = Depends(get_writable_db_session),
) -> SchedulerBulkResultOut:
    return await scheduler_service.reconcile_all_services(session, dry_run=False)


@router.get("/plan/all", response_model=SchedulerBulkResultOut)
async def plan_all_services(
    session: AsyncSession = Depends(get_db_session),
) -> SchedulerBulkResultOut:
    return await scheduler_service.reconcile_all_services(session, dry_run=True)
