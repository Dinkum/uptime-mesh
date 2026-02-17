"""initial schema

Revision ID: 0001_init
Revises:
Create Date: 2026-02-17 00:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cluster_settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )

    op.create_table(
        "nodes",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("mesh_ip", sa.String(length=64), nullable=True),
        sa.Column("status", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_nodes_name", "nodes", ["name"], unique=True)

    op.create_table(
        "services",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=True),
        sa.Column("spec", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("generation", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_services_name", "services", ["name"], unique=True)

    op.create_table(
        "replicas",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("service_id", sa.String(length=64), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column(
            "desired_state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'running'"),
        ),
        sa.Column("status", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"]),
        sa.ForeignKeyConstraint(["node_id"], ["nodes.id"]),
    )

    op.create_table(
        "endpoints",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("replica_id", sa.String(length=64), nullable=False),
        sa.Column("address", sa.String(length=128), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("healthy", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["replica_id"], ["replicas.id"]),
    )

    op.create_table(
        "router_assignments",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("primary_router_id", sa.String(length=64), nullable=False),
        sa.Column("secondary_router_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["node_id"], ["nodes.id"]),
        sa.ForeignKeyConstraint(["primary_router_id"], ["nodes.id"]),
        sa.ForeignKeyConstraint(["secondary_router_id"], ["nodes.id"]),
    )
    op.create_index(
        "ix_router_assignments_node_id", "router_assignments", ["node_id"], unique=False
    )

    op.create_table(
        "events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("fields", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_events_category", "events", ["category"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_events_category", table_name="events")
    op.drop_table("events")

    op.drop_index("ix_router_assignments_node_id", table_name="router_assignments")
    op.drop_table("router_assignments")

    op.drop_table("endpoints")
    op.drop_table("replicas")

    op.drop_index("ix_services_name", table_name="services")
    op.drop_table("services")

    op.drop_index("ix_nodes_name", table_name="nodes")
    op.drop_table("nodes")

    op.drop_table("cluster_settings")
