"""event node id and created_at index

Revision ID: 0010_events_node_created_index
Revises: 0009_events_node_id
Create Date: 2026-05-14 13:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0010_events_node_created_index"
down_revision = "0009_events_node_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("events")}
    if "ix_events_node_id_created_at" not in indexes:
        op.create_index(
            "ix_events_node_id_created_at",
            "events",
            ["node_id", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("events")}
    if "ix_events_node_id_created_at" in indexes:
        op.drop_index("ix_events_node_id_created_at", table_name="events")
