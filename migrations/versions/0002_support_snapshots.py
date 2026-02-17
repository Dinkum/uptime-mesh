"""support bundles and snapshots

Revision ID: 0002_support_snapshots
Revises: 0001_init
Create Date: 2026-02-17 00:05:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0002_support_snapshots"
down_revision = "0001_init"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "snapshot_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column("location", sa.String(length=256), nullable=True),
        sa.Column("requested_by", sa.String(length=128), nullable=True),
        sa.Column("error", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.create_table(
        "support_bundles",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "status", sa.String(length=32), nullable=False, server_default=sa.text("'pending'")
        ),
        sa.Column("path", sa.String(length=256), nullable=True),
        sa.Column("requested_by", sa.String(length=128), nullable=True),
        sa.Column("error", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_table("support_bundles")
    op.drop_table("snapshot_runs")
