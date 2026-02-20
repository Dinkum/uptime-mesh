"""events index and node lease token cleanup

Revision ID: 0006_events_index_and_node_cleanup
Revises: 0005_cluster_settings_value_text
Create Date: 2026-02-20 12:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0006_events_index_and_node_cleanup"
down_revision = "0005_cluster_settings_value_text"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    node_columns = {item["name"] for item in inspector.get_columns("nodes")}
    if "lease_token_hash" in node_columns:
        with op.batch_alter_table("nodes") as batch_op:
            batch_op.drop_column("lease_token_hash")

    event_indexes = {item["name"] for item in inspector.get_indexes("events")}
    if "ix_events_created_at" not in event_indexes:
        op.create_index("ix_events_created_at", "events", ["created_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    event_indexes = {item["name"] for item in inspector.get_indexes("events")}
    if "ix_events_created_at" in event_indexes:
        op.drop_index("ix_events_created_at", table_name="events")

    node_columns = {item["name"] for item in inspector.get_columns("nodes")}
    if "lease_token_hash" not in node_columns:
        with op.batch_alter_table("nodes") as batch_op:
            batch_op.add_column(sa.Column("lease_token_hash", sa.String(length=128), nullable=True))
