from __future__ import annotations

from sqlalchemy import Connection

from migrations.seed.seed_steps import SEED_STEPS


def run_seed_steps(connection: Connection) -> None:
    for seed in SEED_STEPS:
        seed(connection)
