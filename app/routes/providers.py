from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.providers import ProviderAccountCreate, ProviderAccountOut, ProviderSummaryOut
from app.services import providers as provider_service

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("", response_model=ProviderSummaryOut)
async def get_provider_summary(
    session: AsyncSession = Depends(get_db_session),
) -> ProviderSummaryOut:
    return await provider_service.get_summary(session)


@router.post("/accounts", response_model=ProviderAccountOut, status_code=status.HTTP_201_CREATED)
async def upsert_provider_account(
    payload: ProviderAccountCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> ProviderAccountOut:
    try:
        account = await provider_service.upsert_account(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return provider_service.account_out(account)
