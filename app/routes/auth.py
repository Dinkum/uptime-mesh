from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db_session
from app.logger import get_logger
from app.security import (
    SESSION_COOKIE_NAME,
    create_session_token,
    sanitize_next_path,
)
from app.services import auth as auth_service
from app.services import rate_limits as rate_limit_service

router = APIRouter(prefix="/auth", include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")
settings = get_settings()
_logger = get_logger("auth.login")


class TokenLoginRequest(BaseModel):
    username: str
    password: str


def _login_context(
    request: Request,
    *,
    error: Optional[str] = None,
    next_path: str = "/ui",
    status_code: int = status.HTTP_200_OK,
) -> Any:
    context: Dict[str, Any] = {
        "request": request,
        "title": "Sign In",
        "error": error,
        "next_path": next_path,
    }
    return templates.TemplateResponse("login.html", context, status_code=status_code)


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


_LOGIN_MAX_FAILURES = 5
_LOGIN_WINDOW_SECONDS = 60
_LOGIN_LOCKOUT_SECONDS = 300


@router.get("/login")
async def login_page(request: Request, next: str = "/ui") -> Any:
    next_path = sanitize_next_path(next)
    if getattr(request.state, "auth_user", None):
        _logger.info(
            "login.page.redirect",
            "Redirected authenticated user away from login page",
            username=getattr(request.state, "auth_user", ""),
            next_path=next_path,
        )
        return RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)
    _logger.debug("login.page.render", "Rendered login page", next_path=next_path)
    return _login_context(request, next_path=next_path)


@router.post("/login")
async def login_submit(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    username: str = Form(default=""),
    password: str = Form(default=""),
    next: str = Form(default="/ui"),
) -> Any:
    next_path = sanitize_next_path(next)
    client_ip = _client_ip(request)
    normalized_username = username.strip().casefold()
    ip_key = f"ip:{client_ip}"

    async with _logger.operation(
        "login.submit",
        "Handled login form submit",
        username=normalized_username,
        client_ip=client_ip,
    ) as op:
        for key in (ip_key,):
            allowed, retry_after = await rate_limit_service.check_login_lockout(
                session,
                scope="login",
                subject=key,
                window_seconds=_LOGIN_WINDOW_SECONDS,
            )
            op.step(
                "rate_limit.check",
                "Checked login rate limit",
                key=key,
                allowed=allowed,
                retry_after=retry_after,
            )
            if not allowed:
                _logger.warning(
                    "login.blocked",
                    "Blocked login due to rate limit",
                    username=normalized_username,
                    client_ip=client_ip,
                    retry_after=retry_after,
                )
                return _login_context(
                    request,
                    error=f"Too many login attempts. Try again in {retry_after}s.",
                    next_path=next_path,
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )

        op.step("credentials.verify", "Verifying submitted credentials")
        is_valid = await auth_service.verify_credentials(
            session,
            username=username,
            password=password,
        )
        if not is_valid:
            await rate_limit_service.record_login_failure(
                session,
                scope="login",
                subject=ip_key,
                max_failures=_LOGIN_MAX_FAILURES,
                window_seconds=_LOGIN_WINDOW_SECONDS,
                lockout_seconds=_LOGIN_LOCKOUT_SECONDS,
            )
            _logger.warning(
                "login.failed",
                "Rejected invalid login credentials",
                username=normalized_username,
                client_ip=client_ip,
            )
            return _login_context(
                request,
                error="Invalid username or password.",
                next_path=next_path,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        await rate_limit_service.clear_login_lockout(session, scope="login", subject=ip_key)
        op.step("rate_limit.reset", "Reset login rate limiter for successful auth")

        token = create_session_token(
            username=normalized_username,
            secret_key=settings.auth_secret_key,
            ttl_seconds=settings.auth_session_ttl_seconds,
        )
        response = RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=settings.auth_session_ttl_seconds,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="lax",
            path="/",
        )
        _logger.info(
            "login.success",
            "Issued authenticated session cookie",
            username=normalized_username,
            client_ip=client_ip,
            session_ttl_seconds=settings.auth_session_ttl_seconds,
            next_path=next_path,
        )
        return response


@router.get("/logout")
async def logout() -> Any:
    _logger.info("logout.submit", "Processed logout request")
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@router.post("/token")
async def token_login(
    payload: TokenLoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    username = payload.username.strip()
    client_ip = _client_ip(request)
    ip_key = f"ip:{client_ip}"
    normalized_username = username.casefold()

    async with _logger.operation(
        "login.token",
        "Handled token login request",
        username=normalized_username,
        client_ip=client_ip,
    ) as op:
        for key in (ip_key,):
            allowed, retry_after = await rate_limit_service.check_login_lockout(
                session,
                scope="login",
                subject=key,
                window_seconds=_LOGIN_WINDOW_SECONDS,
            )
            op.step(
                "rate_limit.check",
                "Checked login rate limit",
                key=key,
                allowed=allowed,
                retry_after=retry_after,
            )
            if not allowed:
                _logger.warning(
                    "login.blocked",
                    "Blocked token login due to rate limit",
                    username=normalized_username,
                    client_ip=client_ip,
                    retry_after=retry_after,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many login attempts. Try again in {retry_after}s.",
                )

        op.step("credentials.verify", "Verifying submitted credentials")
        is_valid = await auth_service.verify_credentials(
            session,
            username=username,
            password=payload.password,
        )
        if not is_valid:
            await rate_limit_service.record_login_failure(
                session,
                scope="login",
                subject=ip_key,
                max_failures=_LOGIN_MAX_FAILURES,
                window_seconds=_LOGIN_WINDOW_SECONDS,
                lockout_seconds=_LOGIN_LOCKOUT_SECONDS,
            )
            _logger.warning(
                "login.failed",
                "Rejected invalid token login credentials",
                username=normalized_username,
                client_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password."
            )

        await rate_limit_service.clear_login_lockout(session, scope="login", subject=ip_key)
        op.step("rate_limit.reset", "Reset login rate limiter for successful auth")

        token = create_session_token(
            username=normalized_username,
            secret_key=settings.auth_secret_key,
            ttl_seconds=settings.auth_session_ttl_seconds,
        )
        _logger.info(
            "login.success",
            "Issued token login session",
            username=normalized_username,
            client_ip=client_ip,
            session_ttl_seconds=settings.auth_session_ttl_seconds,
        )
        return {
            "session_token": token,
            "cookie_name": SESSION_COOKIE_NAME,
            "expires_in": settings.auth_session_ttl_seconds,
        }
