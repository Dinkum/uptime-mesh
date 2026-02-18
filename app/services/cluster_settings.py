from __future__ import annotations

from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting
from app.services import config_yaml

_logger = get_logger("services.cluster_settings")


async def get_settings_map(session: AsyncSession) -> Dict[str, str]:
    result = await session.execute(select(ClusterSetting))
    settings = {item.key: item.value for item in result.scalars().all()}
    _logger.debug("cluster_settings.list", "Loaded cluster settings", count=len(settings))
    return settings


async def list_settings(session: AsyncSession) -> List[ClusterSetting]:
    result = await session.execute(select(ClusterSetting))
    return list(result.scalars().all())


async def upsert_settings(
    session: AsyncSession,
    updates: Dict[str, str],
    *,
    sync_file: bool = True,
) -> bool:
    if not updates:
        return False
    changed = False
    for key, value in updates.items():
        result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
        setting = result.scalar_one_or_none()
        clean_value = str(value)
        if setting is None:
            session.add(ClusterSetting(key=key, value=clean_value))
            changed = True
        elif setting.value != clean_value:
            setting.value = clean_value
            changed = True
    if changed:
        await session.commit()
        _logger.info("cluster_settings.upsert", "Updated cluster settings", count=len(updates))
        if sync_file:
            await config_yaml.sync_from_db(session)
    return changed


async def set_setting(session: AsyncSession, key: str, value: str) -> ClusterSetting:
    await upsert_settings(session, {key: value}, sync_file=True)
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
    setting = result.scalar_one_or_none()
    if setting is None:
        raise RuntimeError(f"failed to load setting after update: {key}")
    _logger.info("cluster_settings.set", "Updated cluster setting", key=key)
    return setting


async def get_setting(session: AsyncSession, key: str) -> Optional[ClusterSetting]:
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
    return result.scalar_one_or_none()


async def ensure_managed_config(session: AsyncSession) -> None:
    await config_yaml.reconcile_with_db(session)
