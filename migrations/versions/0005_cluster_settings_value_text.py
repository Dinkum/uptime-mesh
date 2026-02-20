"""expand cluster_settings value storage

Revision ID: 0005_cluster_settings_value_text
Revises: 0004_node_identity_signed_leases
Create Date: 2026-02-20 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0005_cluster_settings_value_text"
down_revision = "0004_node_identity_signed_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cluster_settings") as batch_op:
        batch_op.alter_column(
            "value",
            existing_type=sa.String(length=512),
            type_=sa.Text(),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("cluster_settings") as batch_op:
        batch_op.alter_column(
            "value",
            existing_type=sa.Text(),
            type_=sa.String(length=512),
            existing_nullable=False,
        )
