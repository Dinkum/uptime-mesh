from __future__ import annotations

import hmac
import secrets
import string
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.security import hash_password, password_needs_rehash, verify_password
from app.services import cluster_settings

AUTH_USERNAME_KEY = "auth_username"
AUTH_PASSWORD_HASH_KEY = "auth_password_hash"
AUTH_PASSWORD_UPDATED_AT_KEY = "auth_password_updated_at"
DEFAULT_ADMIN_USERNAME = "admin"

_logger = get_logger("services.auth")


def _generate_password_hash() -> str:
    return hash_password(generate_random_password())


def generate_random_password(length: int = 28) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    if length < 16:
        length = 16
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def set_credentials(
    session: AsyncSession,
    *,
    username: str,
    password: str,
) -> None:
    normalized_username = username.strip() or DEFAULT_ADMIN_USERNAME
    password_hash = hash_password(password)
    updated_at = datetime.now(timezone.utc).isoformat()
    await cluster_settings.set_setting(session, AUTH_USERNAME_KEY, normalized_username)
    await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, password_hash)
    await cluster_settings.set_setting(session, AUTH_PASSWORD_UPDATED_AT_KEY, updated_at)
    _logger.info(
        "auth.credentials.set",
        "Set cluster admin credentials",
        username=normalized_username,
    )


async def ensure_auth_defaults(session: AsyncSession) -> Tuple[str, str]:
    username_setting = await cluster_settings.get_setting(session, AUTH_USERNAME_KEY)
    password_hash_setting = await cluster_settings.get_setting(session, AUTH_PASSWORD_HASH_KEY)

    username = (username_setting.value if username_setting else "").strip()
    password_hash = password_hash_setting.value if password_hash_setting else ""
    if not username:
        username = DEFAULT_ADMIN_USERNAME
        await cluster_settings.set_setting(session, AUTH_USERNAME_KEY, username)
        _logger.warning(
            "auth.defaults",
            "Initialized missing auth username setting",
            username=username,
        )
    if not password_hash:
        password_hash = _generate_password_hash()
        await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, password_hash)
        await cluster_settings.set_setting(
            session,
            AUTH_PASSWORD_UPDATED_AT_KEY,
            datetime.now(timezone.utc).isoformat(),
        )
        _logger.warning("auth.defaults", "Initialized missing auth password hash setting")

    return username, password_hash


async def get_username(session: AsyncSession) -> str:
    username, _ = await ensure_auth_defaults(session)
    return username


async def get_login_id(session: AsyncSession) -> str:
    # Backward-compatible alias for older callsites.
    return await get_username(session)


async def verify_credentials(session: AsyncSession, username: str, password: str) -> bool:
    configured_username, configured_hash = await ensure_auth_defaults(session)

    user_ok = hmac.compare_digest(username.strip().casefold(), configured_username.casefold())
    password_ok = verify_password(password, configured_hash)
    if user_ok and password_ok and password_needs_rehash(configured_hash):
        updated_hash = hash_password(password)
        updated_at = datetime.now(timezone.utc).isoformat()
        await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, updated_hash)
        await cluster_settings.set_setting(session, AUTH_PASSWORD_UPDATED_AT_KEY, updated_at)
        _logger.info(
            "auth.password.rehash",
            "Rehashed stored password with current algorithm parameters",
            username=configured_username,
        )
    return user_ok and password_ok


async def change_password(
    session: AsyncSession,
    *,
    username: str,
    current_password: str,
    new_password: str,
) -> tuple[bool, str]:
    configured_username, configured_hash = await ensure_auth_defaults(session)
    if not hmac.compare_digest(username.strip().casefold(), configured_username.casefold()):
        return False, "Authenticated user does not match configured account."
    if not verify_password(current_password, configured_hash):
        return False, "Current password is incorrect."

    updated_hash = hash_password(new_password)
    updated_at = datetime.now(timezone.utc).isoformat()
    await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, updated_hash)
    await cluster_settings.set_setting(session, AUTH_PASSWORD_UPDATED_AT_KEY, updated_at)
    _logger.info("auth.password.update", "Updated admin password", username=configured_username)
    return True, ""
