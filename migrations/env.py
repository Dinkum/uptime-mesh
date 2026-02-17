from __future__ import annotations

import os
from logging.config import fileConfig
from typing import Any, Dict

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from app.config import get_settings
from app.models import Base  # noqa: F401
from migrations.seed.runner import run_seed_steps

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_database_url() -> str:
    url = os.getenv("DATABASE_URL")
    if not url:
        url = get_settings().database_url
    if not url:
        raise RuntimeError("DATABASE_URL is required for migrations.")
    if url.startswith("sqlite+aiosqlite"):
        return url.replace("sqlite+aiosqlite", "sqlite+pysqlite", 1)
    return url


def run_migrations_offline() -> None:
    url = _get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()
        run_seed_steps(connection)


def run_migrations_online() -> None:
    configuration: Dict[str, Any] = {
        "sqlalchemy.url": _get_database_url(),
    }
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
