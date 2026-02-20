from __future__ import annotations

import time
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting
from app.services import config_yaml

_logger = get_logger("services.cluster_settings")
SENSITIVE_CLUSTER_SETTINGS = {"auth_secret_key", "cluster_signing_key"}
_SETTINGS_MAP_TTL_SECONDS = 5.0
_settings_map_cache: Dict[str, str] | None = None
_settings_map_cache_expires_at = 0.0


def _invalidate_settings_map_cache() -> None:
    global _settings_map_cache, _settings_map_cache_expires_at
    _settings_map_cache = None
    _settings_map_cache_expires_at = 0.0


async def get_settings_map(session: AsyncSession) -> Dict[str, str]:
    global _settings_map_cache, _settings_map_cache_expires_at
    now = time.monotonic()
    if _settings_map_cache is not None and now < _settings_map_cache_expires_at:
        _logger.debug(
            "cluster_settings.list_cache_hit",
            "Loaded cluster settings from TTL cache",
            count=len(_settings_map_cache),
        )
        return dict(_settings_map_cache)

    result = await session.execute(select(ClusterSetting))
    settings = {item.key: item.value for item in result.scalars().all()}
    _settings_map_cache = dict(settings)
    _settings_map_cache_expires_at = now + _SETTINGS_MAP_TTL_SECONDS
    _logger.debug("cluster_settings.list", "Loaded cluster settings", count=len(settings))
    return dict(settings)


async def list_settings(session: AsyncSession) -> List[ClusterSetting]:
    result = await session.execute(select(ClusterSetting))
    return list(result.scalars().all())


async def upsert_settings(
    session: AsyncSession,
    updates: Dict[str, str],
    *,
    sync_file: bool = True,
) -> bool:
    return_rows = False
    return await _upsert_settings_internal(
        session,
        updates,
        sync_file=sync_file,
        return_rows=return_rows,
    )


async def upsert_settings_with_rows(
    session: AsyncSession,
    updates: Dict[str, str],
    *,
    sync_file: bool = True,
) -> Dict[str, ClusterSetting]:
    return await _upsert_settings_internal(
        session,
        updates,
        sync_file=sync_file,
        return_rows=True,
    )


async def _upsert_settings_internal(
    session: AsyncSession,
    updates: Dict[str, str],
    *,
    sync_file: bool,
    return_rows: bool,
) -> bool | Dict[str, ClusterSetting]:
    if not updates:
        return {} if return_rows else False

    clean_updates = {str(key).strip(): str(value) for key, value in updates.items() if str(key).strip()}
    keys = list(clean_updates.keys())
    if not keys:
        return {} if return_rows else False

    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key.in_(keys)))
    existing_rows = list(result.scalars().all())
    existing_by_key = {row.key: row for row in existing_rows}
    changed_keys = [key for key in keys if existing_by_key.get(key) is None or existing_by_key[key].value != clean_updates[key]]
    changed = bool(changed_keys)

    if not changed:
        if return_rows:
            return {key: existing_by_key[key] for key in keys if key in existing_by_key}
        return False

    payload = [{"key": key, "value": clean_updates[key]} for key in keys]
    dialect_name = ""
    if session.bind is not None:
        dialect_name = session.bind.dialect.name

    if dialect_name == "sqlite":
        stmt = sqlite_insert(ClusterSetting).values(payload)
        stmt = stmt.on_conflict_do_update(
            index_elements=[ClusterSetting.key],
            set_={"value": stmt.excluded.value},
        )
        await session.execute(stmt)
    else:
        # Fallback path for non-SQLite engines.
        for key in keys:
            value = clean_updates[key]
            setting = existing_by_key.get(key)
            if setting is None:
                session.add(ClusterSetting(key=key, value=value))
            else:
                setting.value = value

    await session.commit()
    _invalidate_settings_map_cache()
    _logger.info(
        "cluster_settings.upsert",
        "Updated cluster settings",
        count=len(keys),
        changed=len(changed_keys),
    )
    if sync_file:
        await config_yaml.sync_from_db(session)

    if not return_rows:
        return True

    rows_result = await session.execute(select(ClusterSetting).where(ClusterSetting.key.in_(keys)))
    rows = rows_result.scalars().all()
    return {row.key: row for row in rows}


async def set_setting(session: AsyncSession, key: str, value: str) -> ClusterSetting:
    rows = await upsert_settings_with_rows(session, {key: value}, sync_file=True)
    setting = rows.get(key)
    if setting is None:
        raise RuntimeError(f"failed to load setting after update: {key}")
    _logger.info("cluster_settings.set", "Updated cluster setting", key=key)
    return setting


async def get_setting(session: AsyncSession, key: str) -> Optional[ClusterSetting]:
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == key))
    return result.scalar_one_or_none()


async def ensure_managed_config(session: AsyncSession) -> None:
    await config_yaml.reconcile_with_db(session)
