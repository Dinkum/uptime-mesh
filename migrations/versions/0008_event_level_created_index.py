"""event level and created_at index

Revision ID: 0008_event_level_created_index
Revises: 0007_replica_endpoint_indexes
Create Date: 2026-05-14 12:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0008_event_level_created_index"
down_revision = "0007_replica_endpoint_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("events")}
    if "ix_events_level_created_at" not in indexes:
        op.create_index(
            "ix_events_level_created_at",
            "events",
            ["level", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("events")}
    if "ix_events_level_created_at" in indexes:
        op.drop_index("ix_events_level_created_at", table_name="events")
