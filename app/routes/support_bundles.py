from __future__ import annotations

from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_incident_db_session
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
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_incident_db_session),
) -> SupportBundleOut:
    if payload.id and await support_bundle_service.get_support_bundle(session, payload.id):
        raise HTTPException(status_code=409, detail="Support bundle id already exists")
    bundle = await support_bundle_service.create_support_bundle_during_incident(session, payload)
    background_tasks.add_task(support_bundle_service.run_support_bundle_job, bundle.id)
    return SupportBundleOut.model_validate(bundle)


@router.get("/{bundle_id}/download")
async def download_support_bundle(
    bundle_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    bundle = await support_bundle_service.get_support_bundle(session, bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Support bundle not found")
    try:
        path = support_bundle_service.support_bundle_artifact_path(bundle)
    except ValueError:
        raise HTTPException(status_code=409, detail="Support bundle artifact is not available")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Support bundle artifact file is missing")
    return FileResponse(
        path=str(path),
        filename=f"{bundle_id}.tar.gz",
        media_type="application/gzip",
    )
