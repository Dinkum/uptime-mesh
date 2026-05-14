"""replica and endpoint lookup indexes

Revision ID: 0007_replica_endpoint_indexes
Revises: 0006_events_index_and_node_cleanup
Create Date: 2026-05-14 12:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0007_replica_endpoint_indexes"
down_revision = "0006_events_index_and_node_cleanup"
branch_labels = None
depends_on = None


def _index_names(table_name: str) -> set[str]:
    return {str(item["name"]) for item in sa.inspect(op.get_bind()).get_indexes(table_name) if item.get("name")}


def upgrade() -> None:
    replica_indexes = _index_names("replicas")
    if "ix_replicas_service_id" not in replica_indexes:
        op.create_index("ix_replicas_service_id", "replicas", ["service_id"], unique=False)
    if "ix_replicas_node_id" not in replica_indexes:
        op.create_index("ix_replicas_node_id", "replicas", ["node_id"], unique=False)

    endpoint_indexes = _index_names("endpoints")
    if "ix_endpoints_replica_id" not in endpoint_indexes:
        op.create_index("ix_endpoints_replica_id", "endpoints", ["replica_id"], unique=False)
    if "ix_endpoints_healthy_replica_id" not in endpoint_indexes:
        op.create_index(
            "ix_endpoints_healthy_replica_id",
            "endpoints",
            ["healthy", "replica_id"],
            unique=False,
        )


def downgrade() -> None:
    endpoint_indexes = _index_names("endpoints")
    if "ix_endpoints_healthy_replica_id" in endpoint_indexes:
        op.drop_index("ix_endpoints_healthy_replica_id", table_name="endpoints")
    if "ix_endpoints_replica_id" in endpoint_indexes:
        op.drop_index("ix_endpoints_replica_id", table_name="endpoints")

    replica_indexes = _index_names("replicas")
    if "ix_replicas_node_id" in replica_indexes:
        op.drop_index("ix_replicas_node_id", table_name="replicas")
    if "ix_replicas_service_id" in replica_indexes:
        op.drop_index("ix_replicas_service_id", table_name="replicas")
