from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.security import hash_password, verify_password
from app.services import cluster_settings

AUTH_USERNAME_KEY = "auth_username"
AUTH_PASSWORD_HASH_KEY = "auth_password_hash"
AUTH_PASSWORD_UPDATED_AT_KEY = "auth_password_updated_at"

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD_HASH = (
    "pbkdf2_sha256$120000$d95113ec8b7f0bd6ebf3644a72a6d89d$"
    "8f0ddafd75770b8947c26e843f6c4ffd7ec198bc762920dc3b905dbdd1bc37f3"
)

_logger = get_logger("services.auth")


async def ensure_auth_defaults(session: AsyncSession) -> Tuple[str, str]:
    username_setting = await cluster_settings.get_setting(session, AUTH_USERNAME_KEY)
    password_hash_setting = await cluster_settings.get_setting(session, AUTH_PASSWORD_HASH_KEY)

    username = username_setting.value if username_setting else ""
    password_hash = password_hash_setting.value if password_hash_setting else ""
    if not username:
        username = DEFAULT_USERNAME
        await cluster_settings.set_setting(session, AUTH_USERNAME_KEY, username)
        _logger.warning("auth.defaults", "Initialized missing auth username setting")
    if not password_hash:
        password_hash = DEFAULT_PASSWORD_HASH
        await cluster_settings.set_setting(session, AUTH_PASSWORD_HASH_KEY, password_hash)
        _logger.warning("auth.defaults", "Initialized missing auth password hash setting")

    return username, password_hash


async def get_username(session: AsyncSession) -> str:
    username, _ = await ensure_auth_defaults(session)
    return username


async def verify_credentials(session: AsyncSession, username: str, password: str) -> bool:
    configured_username, configured_hash = await ensure_auth_defaults(session)

    user_ok = hmac.compare_digest(username.strip().casefold(), configured_username.casefold())
    password_ok = verify_password(password, configured_hash)
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
