from __future__ import annotations

from contextlib import asynccontextmanager
from time import perf_counter
from typing import AsyncIterator, Awaitable, Callable, Optional
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from app.config import (
    DEFAULT_AUTH_SECRET_KEY,
    DEFAULT_CLUSTER_SIGNING_KEY,
    get_settings,
)
from app.logger import configure_logging, get_logger
from app.routes import (
    auth,
    cluster,
    cluster_settings,
    endpoints,
    events,
    nodes,
    replicas,
    router_assignments,
    scheduler,
    services,
    snapshots,
    support_bundles,
    system,
    ui,
    wireguard,
)
from app.security import SESSION_COOKIE_NAME, decode_session_token

settings = get_settings()
configure_logging(settings.log_level, settings.log_file)
logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("app.startup", "Starting app", env=settings.app_env, version=settings.app_version)
    if settings.app_env.strip().lower() not in {"prod", "production"}:
        if settings.auth_secret_key == DEFAULT_AUTH_SECRET_KEY:
            logger.warning(
                "security.defaults",
                "AUTH_SECRET_KEY is using a default placeholder; set a unique secret before production",
            )
        if settings.cluster_signing_key == DEFAULT_CLUSTER_SIGNING_KEY:
            logger.warning(
                "security.defaults",
                "CLUSTER_SIGNING_KEY is using a default placeholder; set a unique secret before production",
            )
        if not settings.auth_cookie_secure:
            logger.warning(
                "security.cookies",
                "AUTH_COOKIE_SECURE is disabled; enable it when serving over HTTPS",
            )
    yield
    logger.info("app.shutdown", "Shutting down app")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)


@app.middleware("http")
async def auth_guard(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    path = request.url.path
    public_paths = {
        "/",
        "/health",
        "/version",
        "/auth/login",
        "/auth/logout",
        "/cluster/join",
        "/cluster/heartbeat",
        "/favicon.ico",
    }
    token = request.cookies.get(SESSION_COOKIE_NAME)
    username = decode_session_token(token or "", settings.auth_secret_key)
    if username:
        request.state.auth_user = username

    if path in public_paths or path.startswith("/auth/"):
        return await call_next(request)

    if username:
        return await call_next(request)

    if path.startswith("/ui"):
        next_path = path
        if request.url.query:
            next_path = f"{path}?{request.url.query}"
        query = urlencode({"next": next_path})
        return RedirectResponse(url=f"/auth/login?{query}", status_code=303)

    return JSONResponse(status_code=401, content={"detail": "Authentication required"})


@app.middleware("http")
async def request_logging(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    request_id = request.headers.get("x-request-id") or str(uuid4())
    client: Optional[str] = None
    if request.client:
        client = request.client.host

    start = perf_counter()
    with logger.context(request_id=request_id):
        logger.info(
            "request.start",
            "Started",
            method=request.method,
            path=request.url.path,
            client=client,
        )
        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = (perf_counter() - start) * 1000
            logger.exception(
                "request.error",
                "Failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 1),
                error_type=type(exc).__name__,
            )
            raise

        duration_ms = (perf_counter() - start) * 1000
        logger.info(
            "request.complete",
            "Completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 1),
        )

    response.headers["X-Request-ID"] = request_id
    return response


app.include_router(system.router)
app.include_router(auth.router)
app.include_router(cluster.router)
app.include_router(nodes.router)
app.include_router(services.router)
app.include_router(replicas.router)
app.include_router(endpoints.router)
app.include_router(router_assignments.router)
app.include_router(scheduler.router)
app.include_router(events.router)
app.include_router(snapshots.router)
app.include_router(support_bundles.router)
app.include_router(cluster_settings.router)
app.include_router(wireguard.router)
app.include_router(ui.router)
