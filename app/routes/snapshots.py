from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.snapshots import SnapshotRunCreate, SnapshotRunOut
from app.services import snapshots as snapshot_service

router = APIRouter(prefix="/etcd/snapshots", tags=["snapshots"])


@router.get("", response_model=List[SnapshotRunOut])
async def list_snapshots(
    session: AsyncSession = Depends(get_db_session),
) -> List[SnapshotRunOut]:
    snapshots = await snapshot_service.list_snapshots(session)
    return [SnapshotRunOut.model_validate(snapshot) for snapshot in snapshots]


@router.post("", response_model=SnapshotRunOut, status_code=status.HTTP_201_CREATED)
async def request_snapshot(
    payload: SnapshotRunCreate,
    session: AsyncSession = Depends(get_writable_db_session),
) -> SnapshotRunOut:
    if payload.id and await snapshot_service.get_snapshot(session, payload.id):
        raise HTTPException(status_code=409, detail="Snapshot id already exists")
    snapshot = await snapshot_service.create_snapshot(session, payload)
    return SnapshotRunOut.model_validate(snapshot)


@router.get("/{snapshot_id}/download")
async def download_snapshot(
    snapshot_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    snapshot = await snapshot_service.get_snapshot(session, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if not snapshot.location:
        raise HTTPException(status_code=409, detail="Snapshot artifact is not available")
    path = Path(snapshot.location)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Snapshot artifact file is missing")
    return FileResponse(path=str(path), filename=f"{snapshot_id}.db", media_type="application/octet-stream")
