from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.support_bundles import SupportBundleCreate, SupportBundleOut
from app.services import support_bundles as support_bundle_service

router = APIRouter(prefix="/support-bundles", tags=["support-bundles"])


@router.get("", response_model=List[SupportBundleOut])
async def list_support_bundles(
    session: AsyncSession = Depends(get_db_session),
) -> List[SupportBundleOut]:
    bundles = await support_bundle_service.list_support_bundles(session)
    return [SupportBundleOut.model_validate(bundle) for bundle in bundles]


@router.post("", response_model=SupportBundleOut, status_code=status.HTTP_201_CREATED)
async def request_support_bundle(
    payload: SupportBundleCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> SupportBundleOut:
    if payload.id and await support_bundle_service.get_support_bundle(session, payload.id):
        raise HTTPException(status_code=409, detail="Support bundle id already exists")
    bundle = await support_bundle_service.create_support_bundle(session, payload)
    return SupportBundleOut.model_validate(bundle)
