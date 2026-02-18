from __future__ import annotations

import hmac
import secrets
import string
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.security import generate_login_id, hash_password, password_needs_rehash, verify_password
from app.services import cluster_settings

AUTH_USERNAME_KEY = "auth_username"
AUTH_PASSWORD_HASH_KEY = "auth_password_hash"
AUTH_PASSWORD_UPDATED_AT_KEY = "auth_password_updated_at"

_logger = get_logger("services.auth")


def _generate_login_id() -> str:
    return generate_login_id(16)


def _generate_password_hash() -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    password = "".join(secrets.choice(alphabet) for _ in range(28))
    return hash_password(password)


async def ensure_auth_defaults(session: AsyncSession) -> Tuple[str, str]:
    login_id_setting = await cluster_settings.get_setting(session, AUTH_USERNAME_KEY)
    password_hash_setting = await cluster_settings.get_setting(session, AUTH_PASSWORD_HASH_KEY)

    login_id = login_id_setting.value if login_id_setting else ""
    password_hash = password_hash_setting.value if password_hash_setting else ""
    if not login_id:
        login_id = _generate_login_id()
        await cluster_settings.set_setting(session, AUTH_USERNAME_KEY, login_id)
        _logger.warning(
            "auth.defaults",
            "Initialized missing auth login ID setting",
            login_id=login_id,
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

    return login_id, password_hash


async def get_login_id(session: AsyncSession) -> str:
    login_id, _ = await ensure_auth_defaults(session)
    return login_id


async def get_username(session: AsyncSession) -> str:
    return await get_login_id(session)


async def verify_credentials(session: AsyncSession, username: str, password: str) -> bool:
    configured_login_id, configured_hash = await ensure_auth_defaults(session)

    user_ok = hmac.compare_digest(username.strip().casefold(), configured_login_id.casefold())
    password_ok = verify_password(password, configured_hash)
    if user_ok and password_ok and password_needs_rehash(configured_hash):
        updated_hash = hash_password(password)
        updated_at = datetime.now(timezone.utc).isoformat()
        await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, updated_hash)
        await cluster_settings.set_setting(session, AUTH_PASSWORD_UPDATED_AT_KEY, updated_at)
        _logger.info(
            "auth.password.rehash",
            "Rehashed stored password with current algorithm parameters",
            login_id=configured_login_id,
        )
    return user_ok and password_ok


async def change_password(
    session: AsyncSession,
    *,
    username: str,
    current_password: str,
    new_password: str,
) -> tuple[bool, str]:
    configured_login_id, configured_hash = await ensure_auth_defaults(session)
    if not hmac.compare_digest(username.strip().casefold(), configured_login_id.casefold()):
        return False, "Authenticated user does not match configured account."
    if not verify_password(current_password, configured_hash):
        return False, "Current password is incorrect."

    updated_hash = hash_password(new_password)
    updated_at = datetime.now(timezone.utc).isoformat()
    await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, updated_hash)
    await cluster_settings.set_setting(session, AUTH_PASSWORD_UPDATED_AT_KEY, updated_at)
    _logger.info("auth.password.update", "Updated admin password", login_id=configured_login_id)
    return True, ""
