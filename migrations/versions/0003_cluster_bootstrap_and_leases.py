"""cluster bootstrap enrollment and leases

Revision ID: 0003_cluster_bootstrap_and_leases
Revises: 0002_support_snapshots
Create Date: 2026-02-17 06:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0003_cluster_bootstrap_and_leases"
down_revision = "0002_support_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("nodes", sa.Column("api_endpoint", sa.String(length=256), nullable=True))
    op.add_column("nodes", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("nodes", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("nodes", sa.Column("lease_token_hash", sa.String(length=128), nullable=True))

    op.create_table(
        "join_tokens",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("issued_by", sa.String(length=128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_join_tokens_token_hash", "join_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_join_tokens_token_hash", table_name="join_tokens")
    op.drop_table("join_tokens")

    op.drop_column("nodes", "lease_token_hash")
    op.drop_column("nodes", "lease_expires_at")
    op.drop_column("nodes", "heartbeat_at")
    op.drop_column("nodes", "api_endpoint")
