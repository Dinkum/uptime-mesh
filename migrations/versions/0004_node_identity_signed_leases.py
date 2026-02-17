"""node identity and signed lease flow

Revision ID: 0004_node_identity_signed_leases
Revises: 0003_cluster_bootstrap_and_leases
Create Date: 2026-02-17 07:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0004_node_identity_signed_leases"
down_revision = "0003_cluster_bootstrap_and_leases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("nodes", sa.Column("identity_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("nodes", sa.Column("identity_cert_pem", sa.String(length=8192), nullable=True))
    op.add_column("nodes", sa.Column("identity_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("nodes", "identity_expires_at")
    op.drop_column("nodes", "identity_cert_pem")
    op.drop_column("nodes", "identity_fingerprint")
