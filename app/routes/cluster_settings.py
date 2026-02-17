from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session
from app.schemas.cluster_settings import ClusterSettingOut, ClusterSettingUpsert
from app.services import cluster_settings as cluster_settings_service

router = APIRouter(prefix="/cluster-settings", tags=["cluster-settings"])


@router.get("", response_model=List[ClusterSettingOut])
async def list_cluster_settings(
    session: AsyncSession = Depends(get_db_session),
) -> List[ClusterSettingOut]:
    settings = await cluster_settings_service.list_settings(session)
    return [ClusterSettingOut.model_validate(item) for item in settings]


@router.get("/{key}", response_model=ClusterSettingOut)
async def get_cluster_setting(
    key: str,
    session: AsyncSession = Depends(get_db_session),
) -> ClusterSettingOut:
    setting = await cluster_settings_service.get_setting(session, key)
    if setting is None:
        raise HTTPException(status_code=404, detail="Cluster setting not found")
    return ClusterSettingOut.model_validate(setting)


@router.put("/{key}", response_model=ClusterSettingOut, status_code=status.HTTP_200_OK)
async def put_cluster_setting(
    key: str,
    payload: ClusterSettingUpsert,
    session: AsyncSession = Depends(get_db_session),
) -> ClusterSettingOut:
    setting = await cluster_settings_service.set_setting(session, key, payload.value)
    return ClusterSettingOut.model_validate(setting)
