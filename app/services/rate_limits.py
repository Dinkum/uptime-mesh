from __future__ import annotations

import hashlib
import json
import math
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting

_logger = get_logger("services.rate_limits")


def _key(prefix: str, scope: str, subject: str) -> str:
    scope_slug = "".join(ch for ch in scope.strip().lower() if ch.isalnum())[:12] or "scope"
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:40]
    return f"{prefix}:{scope_slug}:{digest}"


def _default_state() -> dict[str, Any]:
    return {"attempts": [], "blocked_until": 0}


def _parse_state(raw: str, *, setting_key: str) -> dict[str, Any]:
    if not raw.strip():
        return _default_state()
    try:
        payload = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "rate_limit.state_decode",
            "Failed parsing persisted limiter state, resetting",
            setting_key=setting_key,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return _default_state()
    if not isinstance(payload, dict):
        return _default_state()
    attempts_raw = payload.get("attempts")
    attempts: list[int] = []
    if isinstance(attempts_raw, list):
        for value in attempts_raw:
            try:
                timestamp = int(value)
            except Exception:  # noqa: BLE001
                continue
            if timestamp > 0:
                attempts.append(timestamp)
    blocked_until_raw = payload.get("blocked_until", 0)
    try:
        blocked_until = int(blocked_until_raw)
    except Exception:  # noqa: BLE001
        blocked_until = 0
    return {"attempts": attempts, "blocked_until": max(0, blocked_until)}


def _prune_attempts(attempts: list[int], *, now_epoch: int, window_seconds: int) -> list[int]:
    threshold = now_epoch - max(1, window_seconds)
    return [timestamp for timestamp in attempts if timestamp >= threshold]


async def _load_setting(session: AsyncSession, setting_key: str) -> ClusterSetting | None:
    result = await session.execute(select(ClusterSetting).where(ClusterSetting.key == setting_key))
    return result.scalar_one_or_none()


async def _store_state(
    session: AsyncSession,
    *,
    setting: ClusterSetting | None,
    setting_key: str,
    state: dict[str, Any],
) -> None:
    encoded = json.dumps(state, separators=(",", ":"), sort_keys=True)
    if setting is None:
        session.add(ClusterSetting(key=setting_key, value=encoded))
    else:
        setting.value = encoded
    await session.commit()


async def _clear_state(session: AsyncSession, *, setting: ClusterSetting | None) -> None:
    if setting is None:
        return
    await session.delete(setting)
    await session.commit()


async def check_login_lockout(
    session: AsyncSession,
    *,
    scope: str,
    subject: str,
    window_seconds: int,
) -> tuple[bool, int]:
    now_epoch = int(time.time())
    setting_key = _key("lockout", scope, subject)
    setting = await _load_setting(session, setting_key)
    if setting is None:
        return True, 0

    state = _parse_state(setting.value, setting_key=setting_key)
    attempts = _prune_attempts(
        list(state.get("attempts", [])),
        now_epoch=now_epoch,
        window_seconds=window_seconds,
    )
    blocked_until = int(state.get("blocked_until", 0) or 0)
    changed = attempts != list(state.get("attempts", []))

    if blocked_until > now_epoch:
        retry_after = max(1, int(math.ceil(blocked_until - now_epoch)))
        if changed:
            await _store_state(
                session,
                setting=setting,
                setting_key=setting_key,
                state={"attempts": attempts, "blocked_until": blocked_until},
            )
        return False, retry_after

    # Lockout expired; clear stale limiter state when there are no recent attempts.
    if blocked_until > 0 or changed:
        if attempts:
            await _store_state(
                session,
                setting=setting,
                setting_key=setting_key,
                state={"attempts": attempts, "blocked_until": 0},
            )
        else:
            await _clear_state(session, setting=setting)
    return True, 0


async def record_login_failure(
    session: AsyncSession,
    *,
    scope: str,
    subject: str,
    max_failures: int,
    window_seconds: int,
    lockout_seconds: int,
) -> None:
    now_epoch = int(time.time())
    setting_key = _key("lockout", scope, subject)
    setting = await _load_setting(session, setting_key)
    state = _parse_state(setting.value, setting_key=setting_key) if setting else _default_state()
    attempts = _prune_attempts(
        list(state.get("attempts", [])),
        now_epoch=now_epoch,
        window_seconds=window_seconds,
    )
    attempts.append(now_epoch)
    blocked_until = 0
    if len(attempts) >= max(1, max_failures):
        blocked_until = now_epoch + max(1, lockout_seconds)
        attempts = []

    await _store_state(
        session,
        setting=setting,
        setting_key=setting_key,
        state={"attempts": attempts, "blocked_until": blocked_until},
    )


async def clear_login_lockout(session: AsyncSession, *, scope: str, subject: str) -> None:
    setting_key = _key("lockout", scope, subject)
    setting = await _load_setting(session, setting_key)
    await _clear_state(session, setting=setting)


async def consume_request_limit(
    session: AsyncSession,
    *,
    scope: str,
    subject: str,
    max_requests: int,
    window_seconds: int,
) -> tuple[bool, int]:
    now_epoch = int(time.time())
    setting_key = _key("rate", scope, subject)
    setting = await _load_setting(session, setting_key)
    state = _parse_state(setting.value, setting_key=setting_key) if setting else _default_state()
    attempts = _prune_attempts(
        list(state.get("attempts", [])),
        now_epoch=now_epoch,
        window_seconds=window_seconds,
    )

    limit = max(1, max_requests)
    if len(attempts) >= limit:
        retry_after = max(1, window_seconds - max(0, now_epoch - attempts[0]))
        await _store_state(
            session,
            setting=setting,
            setting_key=setting_key,
            state={"attempts": attempts, "blocked_until": now_epoch + retry_after},
        )
        return False, retry_after

    attempts.append(now_epoch)
    await _store_state(
        session,
        setting=setting,
        setting_key=setting_key,
        state={"attempts": attempts, "blocked_until": 0},
    )
    return True, 0
