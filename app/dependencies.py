from __future__ import annotations

from functools import lru_cache
from time import perf_counter
from typing import Any, AsyncIterator
from uuid import uuid4

from fastapi import Depends, HTTPException
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings, get_settings
from app.logger import get_logger
from app.services.cluster_settings import get_setting

_DB_LOGGER = get_logger("db")
_DB_SESSION_LOGGER = get_logger("db.session")
_DB_GUARD_LOGGER = get_logger("db.guard")
_QUERY_CONTEXT_STACK_KEY = "uptimemesh_query_stack"


def _truncate(value: str, max_length: int) -> str:
    if max_length <= 0 or len(value) <= max_length:
        return value
    if max_length <= 3:
        return value[:max_length]
    return f"{value[: max_length - 3]}..."


def _compact_whitespace(value: str) -> str:
    return " ".join(value.split())


def _format_sql(statement: Any, max_length: int) -> str:
    return _truncate(_compact_whitespace(str(statement or "")), max_length)


def _format_params(parameters: Any, max_length: int) -> str:
    return _truncate(_compact_whitespace(repr(parameters)), max_length)


def _get_query_stack(connection: Any) -> list[dict[str, Any]]:
    stack = connection.info.get(_QUERY_CONTEXT_STACK_KEY)
    if isinstance(stack, list):
        return stack
    stack = []
    connection.info[_QUERY_CONTEXT_STACK_KEY] = stack
    return stack


def _install_query_logging(
    engine: AsyncEngine,
    *,
    database_url: str,
    settings: Settings,
) -> None:
    sync_engine = engine.sync_engine
    if getattr(sync_engine, "_uptimemesh_query_logging", False):
        return
    setattr(sync_engine, "_uptimemesh_query_logging", True)

    @event.listens_for(sync_engine, "before_cursor_execute")
    def _before_cursor_execute(
        conn: Any,
        cursor: Any,
        statement: Any,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        del cursor, context
        stack = _get_query_stack(conn)
        stack.append(
            {
                "start": perf_counter(),
                "statement": statement,
                "parameters": parameters,
                "executemany": executemany,
            }
        )

    @event.listens_for(sync_engine, "after_cursor_execute")
    def _after_cursor_execute(
        conn: Any,
        cursor: Any,
        statement: Any,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        del statement, parameters, context, executemany
        stack = _get_query_stack(conn)
        query_context = stack.pop() if stack else {}
        started_at = float(query_context.get("start", perf_counter()))
        duration_ms = (perf_counter() - started_at) * 1000

        if not settings.log_db_queries:
            return

        fields: dict[str, Any] = {
            "duration_ms": round(duration_ms, 1),
            "rowcount": getattr(cursor, "rowcount", None),
            "executemany": bool(query_context.get("executemany")),
            "sql": _format_sql(query_context.get("statement"), settings.log_sql_max_length),
            "db": database_url.split("://", maxsplit=1)[0],
            "connection_id": id(conn),
        }
        if settings.log_db_query_params:
            fields["params"] = _format_params(
                query_context.get("parameters"),
                settings.log_sql_max_length,
            )
        _DB_LOGGER.info("query.execute", "Executed SQL statement", **fields)

        if duration_ms >= 200:
            _DB_LOGGER.warning(
                "query.slow",
                "Slow SQL statement",
                duration_ms=round(duration_ms, 1),
                sql=_format_sql(query_context.get("statement"), settings.log_sql_max_length),
                connection_id=id(conn),
            )

    @event.listens_for(sync_engine, "handle_error")
    def _handle_error(exception_context: Any) -> None:
        connection = exception_context.connection
        started_at: float | None = None
        if connection is not None:
            stack = _get_query_stack(connection)
            query_context = stack.pop() if stack else {}
            if query_context:
                started_at = float(query_context.get("start", perf_counter()))

        duration_ms: float | None = None
        if started_at is not None:
            duration_ms = (perf_counter() - started_at) * 1000

        fields: dict[str, Any] = {
            "error_type": type(exception_context.original_exception).__name__,
            "error": str(exception_context.original_exception),
            "sql": _format_sql(exception_context.statement, settings.log_sql_max_length),
        }
        if duration_ms is not None:
            fields["duration_ms"] = round(duration_ms, 1)
        if settings.log_db_query_params:
            fields["params"] = _format_params(
                exception_context.parameters,
                settings.log_sql_max_length,
            )
        if connection is not None:
            fields["connection_id"] = id(connection)
        _DB_LOGGER.error("query.error", "SQL execution failed", **fields)


@lru_cache
def get_engine(database_url: str) -> AsyncEngine:
    settings = get_settings()
    engine = create_async_engine(
        database_url,
        pool_pre_ping=True,
    )

    if database_url.startswith("sqlite"):

        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragma(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _install_query_logging(engine, database_url=database_url, settings=settings)
    return engine


@lru_cache
def get_sessionmaker(database_url: str) -> async_sessionmaker[AsyncSession]:
    engine = get_engine(database_url)
    return async_sessionmaker(bind=engine, expire_on_commit=False)


async def get_db_session(
    settings: Settings = Depends(get_settings),
) -> AsyncIterator[AsyncSession]:
    sessionmaker = get_sessionmaker(settings.database_url)
    session_id = uuid4().hex[:12]
    start = perf_counter()

    with _DB_SESSION_LOGGER.context(db_session_id=session_id):
        _DB_SESSION_LOGGER.info("session.open", "Opened DB session")
        async with sessionmaker() as session:
            try:
                yield session
            except Exception as exc:
                if session.in_transaction():
                    await session.rollback()
                    _DB_SESSION_LOGGER.warning(
                        "session.rollback",
                        "Rolled back DB transaction after error",
                        error_type=type(exc).__name__,
                    )
                _DB_SESSION_LOGGER.exception(
                    "session.error",
                    "DB session failed",
                    error_type=type(exc).__name__,
                )
                raise
            finally:
                duration_ms = (perf_counter() - start) * 1000
                _DB_SESSION_LOGGER.info(
                    "session.close",
                    "Closed DB session",
                    duration_ms=round(duration_ms, 1),
                )


async def get_writable_db_session(
    session: AsyncSession = Depends(get_db_session),
) -> AsyncSession:
    etcd_status = await get_setting(session, "etcd_status")
    status_value = etcd_status.value.lower() if etcd_status is not None else "unknown"
    _DB_GUARD_LOGGER.info("write_guard.check", "Checked etcd write guard", etcd_status=status_value)

    if etcd_status is None:
        return session

    blocked_states = {"down", "unavailable", "stale"}
    if etcd_status.value.lower() in blocked_states:
        _DB_GUARD_LOGGER.warning(
            "write_guard.block",
            "Rejected write while etcd is unavailable",
            etcd_status=etcd_status.value.lower(),
        )
        raise HTTPException(
            status_code=503,
            detail="Cluster writes are disabled while etcd is unavailable or stale.",
        )
    _DB_GUARD_LOGGER.info(
        "write_guard.allow",
        "Allowed write request",
        etcd_status=etcd_status.value.lower(),
    )
    return session
