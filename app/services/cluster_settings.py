from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting

_logger = get_logger("services.cluster_settings")


async def get_settings_map(session: AsyncSession) -> Dict[str, str]:
    result = await session.execute(select(ClusterSetting))
    settings = {item.key: item.value for item in result.scalars().all()}
    _logger.debug("cluster_settings.list", "Loaded cluster settings", count=len(settings))
    return settings


async def list_settings(session: AsyncSession) -> List[ClusterSetting]:
    result = await session.execute(select(ClusterSetting))
    return list(result.scalars().all())


async def set_setting(session: AsyncSession, key: str, value: str) -> ClusterSetting:
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
    setting = result.scalar_one_or_none()
    if setting is None:
        setting = ClusterSetting(key=key, value=value)
        session.add(setting)
    else:
        setting.value = value

    await session.commit()
    await session.refresh(setting)
    _logger.info("cluster_settings.set", "Updated cluster setting", key=key)
    return setting


async def get_setting(session: AsyncSession, key: str) -> Optional[ClusterSetting]:
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
    return result.scalar_one_or_none()
