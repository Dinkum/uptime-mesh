"""event node id lookup column

Revision ID: 0009_events_node_id
Revises: 0008_event_level_created_index
Create Date: 2026-05-14 12:45:00.000000
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "0009_events_node_id"
down_revision = "0008_event_level_created_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {item["name"] for item in inspector.get_columns("events")}
    if "node_id" not in columns:
        with op.batch_alter_table("events") as batch_op:
            batch_op.add_column(sa.Column("node_id", sa.String(length=64), nullable=True))

    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT id, fields FROM events WHERE node_id IS NULL")
    ).fetchall()
    candidate_keys = (
        "node_id",
        "target_node_id",
        "source_node_id",
        "peer_node_id",
        "member_name",
    )
    for event_id, raw_fields in rows:
        fields = raw_fields
        if isinstance(raw_fields, str):
            try:
                fields = json.loads(raw_fields)
            except json.JSONDecodeError:
                fields = {}
        if not isinstance(fields, dict):
            continue
        node_id = ""
        for key in candidate_keys:
            value = fields.get(key)
            if isinstance(value, str) and value.strip():
                node_id = value.strip()
                break
        if node_id:
            connection.execute(
                sa.text("UPDATE events SET node_id = :node_id WHERE id = :event_id"),
                {"node_id": node_id, "event_id": event_id},
            )

    indexes = {item["name"] for item in sa.inspect(op.get_bind()).get_indexes("events")}
    if "ix_events_node_id" not in indexes:
        op.create_index("ix_events_node_id", "events", ["node_id"], unique=False)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {item["name"] for item in inspector.get_indexes("events")}
    if "ix_events_node_id" in indexes:
        op.drop_index("ix_events_node_id", table_name="events")

    columns = {item["name"] for item in sa.inspect(op.get_bind()).get_columns("events")}
    if "node_id" in columns:
        with op.batch_alter_table("events") as batch_op:
            batch_op.drop_column("node_id")
